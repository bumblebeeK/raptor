// Copyright EasyStack. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package pool

import (
	"context"
	"fmt"
	"github.com/easystack/raptor/pkg/allocator"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/k8s"
	"github.com/easystack/raptor/pkg/storage"
	"github.com/easystack/raptor/pkg/types"
	"reflect"
	"sync"
	"time"
)

var log = base.NewLogWithField("sub_sys", "pool")

// AllocationMap is a map of allocated IPs indexed by IP
type AllocationMap struct {
	data    map[string]*AllocationIP
	mutex   sync.RWMutex
	service k8s.Service
}

// AllocationIP is an IP which is available for allocation, or already
// has been allocated
type AllocationIP struct {
	// Owner is the owner of the IP.
	Owner string

	Resource types.VPCIP
}

func (a *AllocationMap) occupyIP(owner string, prefer string) (types.VPCIP, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if prefer != "" {
		if ip, ok := a.data[prefer]; ok {
			if ip.Owner == owner || ip.Owner == "" {
				a.data[prefer].Owner = owner
				return ip.Resource, nil
			} else {
				return nil, fmt.Errorf("%s is owned by %s, can't allocate", prefer, owner)
			}
		} else {
			return nil, fmt.Errorf("resouce %s not found on this node", prefer)
		}
	}

	for key := range a.data {
		reserved, _ := a.service.GetIfResourceReserved(context.TODO(), key)
		if a.data[key].Owner == "" && !reserved {
			a.data[key].Owner = owner
			return a.data[key].Resource, nil
		}
	}

	return nil, fmt.Errorf("no more ip available")
}

func (a *AllocationMap) returnIP(resourceId string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if _, ok := a.data[resourceId]; ok {
		a.data[resourceId].Owner = ""
		return
	}

	log.Errorf("resource %s is not allocated.", resourceId)
}

func (a *AllocationMap) addIP(vpcIP types.VPCIP) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.data[vpcIP.GetResourceId()] = &AllocationIP{
		Resource: vpcIP,
	}
}

func (a *AllocationMap) delIP(resourceId string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.data, resourceId)
}

func (a *AllocationMap) idleCount() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	cnt := 0
	for _, ip := range a.data {
		if ip.Owner == "" {
			cnt++
		}
	}
	return cnt
}

func (a *AllocationMap) usedCount() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	cnt := 0
	for _, ip := range a.data {
		if ip.Owner != "" {
			cnt++
		}
	}
	return cnt
}

func (a *AllocationMap) totalCount() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return len(a.data)
}

func (a *AllocationMap) release(count int) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	for key, ip := range a.data {
		if ip.Owner == "" {
			delete(a.data, key)
		}
	}
	return
}

func NewAllocationMap(service k8s.Service) AllocationMap {
	return AllocationMap{data: map[string]*AllocationIP{}, service: service}
}

type PodNetworkPool interface {
	Name() string

	SubnetId() string

	Status() Status

	Allocate(prefer, owner string, staticMode bool) (types.VPCIP, error)

	Release(resourceId string, staticMode bool) error

	SetConfig(config PoolConfig)
}

type pool struct {
	name            string
	subnetId        string
	networkCard     types.NetworkCard
	allocator       allocator.Allocator
	store           storage.Storage[types.VPCIP]
	allocation      AllocationMap
	mutex           sync.Mutex
	config          PoolConfig
	gateway         types.IPSet
	terminated      chan struct{}
	trunkMode       bool
	reconcileStatus bool
	status          PoolStatus
}

func (p *pool) Name() string {
	return p.name
}

func (p *pool) Status() Status {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return Status{
		PoolStatus:     p.status,
		AllocatedCount: p.allocation.usedCount(),
		IdleCount:      p.allocation.idleCount(),
		SubnetId:       p.subnetId,
		TrunkMode:      p.trunkMode,
		TotalCount:     p.allocation.totalCount(),
	}
}

func (p *pool) Allocate(prefer, owner string, staticMode bool) (types.VPCIP, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.status != Active {
		return nil, fmt.Errorf("pool %s isn't active, can't allocate", p.name)
	}

	if staticMode && prefer != "" {
		vpcIP, err := p.allocator.ApplyForVPCIPResource(p.networkCard, p.subnetId, p.name, prefer)
		if err != nil {
			log.Errorf("Pool %s allocate ip error: %s.", p.name, err.Error())
			return nil, err
		}
		err = p.store.Put(vpcIP.GetResourceId(), vpcIP)
		if err != nil {
			log.Errorf("Put vpcip %s to local store error: %s.", vpcIP.GetResourceId(), err.Error())
			return nil, err
		}
		p.allocation.addIP(vpcIP)
	}

	vpcIP, err := p.allocation.occupyIP(owner, prefer)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate vpc ip, error: %v", err)
	}

	return vpcIP, nil
}

func (p *pool) Release(resourceId string, staticMode bool) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.allocation.returnIP(resourceId)

	if staticMode {
		p.allocation.delIP(resourceId)

		vpcIP, err := p.store.Delete(resourceId)
		if err != nil {
			return fmt.Errorf("failed to delete ip from local store, error: %s", err)
		}

		err = p.allocator.ReleaseVPCIPResource(vpcIP, false)
		if err != nil {
			return fmt.Errorf("failed to release vpc ip resource, error: %s", err)
		}
		return nil
	}

	return nil
}

func (p *pool) SubnetId() string {
	return p.subnetId
}

func (p *pool) SetConfig(config PoolConfig) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !reflect.DeepEqual(p.config, config) {
		p.config = config
		log.Infof("Set new config for pool %s, %+v.", p.name, config)
	}

	if p.config.PoolStatus != Unknown {
		p.status = Active
	}
}

func NewPodNetworkPool(ctx context.Context, name string, subnetId string, allocator allocator.Allocator, networkCard types.NetworkCard, storage storage.Storage[types.VPCIP], records []*types.PodRecord, service k8s.Service) PodNetworkPool {
	p := pool{
		name:        name,
		store:       storage,
		networkCard: networkCard,
		subnetId:    subnetId,
		allocation:  NewAllocationMap(service),
		allocator:   allocator,
	}

	for _, vpcip := range p.store.List() {
		vpcip := vpcip.Value
		p.allocation.addIP(vpcip)
	}

	for i := range records {
		_, err := p.allocation.occupyIP(records[i].Owner, records[i].ResourceId)
		if err != nil {
			log.Warnf("Failed to restore ip records for pod %s, error is %s.", records[i].Owner, err.Error())
		}
	}

	log.Infof("Created new pod network %s, idle count: %d, used count: %d, total count: %d.", name, p.allocation.idleCount(), p.allocation.usedCount(), p.allocation.totalCount())

	go p.reconcileLoop(ctx)

	return &p
}

func (p *pool) reconcileLoop(ctx context.Context) {
	log.Infof("Pool %s start reconcile loop", p.name)
	tk := time.Tick(30 * time.Second)
	for {
		select {
		case <-tk:
			p.doReconcile()
		case <-ctx.Done():
			goto stop
		case <-p.terminated:
			goto stop
		}
	}
stop:
	log.Infof("Pool %s stopped reconcile loop", p.name)
}

func (p *pool) doReconcile() {
	log.Infof("Do reconcile for pool %s.", p.name)
	if p.status == Unknown {
		log.Infof("Pool %s hasn't initialized, skip reconcile.", p.name)
		return
	}

	inReconcile, config, poolStatus := p.preReconcile()
	if inReconcile {
		return
	}
	defer p.reconcileEnd()

	log.Infof("Pool %s status is %v,config is %+v.", p.name, poolStatus, p.config)

	totalCount := p.allocation.totalCount()
	usedCount := p.allocation.usedCount()

	if poolStatus == Active {
		allocateOrRelease := calculateNeededOrReleaseIPs(totalCount, usedCount, config.PreAllocate, config.MinAllocate, config.MaxAllocate, config.Watermark)
		if allocateOrRelease > 0 {
			log.Infof("Pool %s need to allocate %d vpc ip.", p.name, allocateOrRelease)
			for i := 0; i < allocateOrRelease; i++ {
				if !p.allocator.JudgeCalleeReady() {
					log.Errorf("Allocator is not ready, waiting for next loop.")
					return
				}
				vpcIP, err := p.allocator.ApplyForVPCIPResource(p.networkCard, p.subnetId, p.name, "")
				if err != nil {
					log.Errorf("Pool %s allocate ip error: %s.", p.name, err.Error())
					return
				}
				err = p.store.Put(vpcIP.GetResourceId(), vpcIP)
				if err != nil {
					log.Errorf("Put vpcip %s to local store error: %s.", vpcIP.GetResourceId(), err.Error())
					return
				}

				p.mutex.Lock()
				p.allocation.addIP(vpcIP)
				p.mutex.Unlock()
				log.Infof("Pool %s added vpcip %s, ip is %+v.", p.name, vpcIP.GetResourceId(), vpcIP.GetIPSet())
			}
		}
		if allocateOrRelease < 0 {
			log.Infof("Pool %s need to release %d vpc ip.", p.name, -allocateOrRelease)

			for i := 0; i < -allocateOrRelease; i++ {
				if !p.allocator.JudgeCalleeReady() {
					log.Errorf("Allocator is not ready, waiting for next loop.")
					return
				}
				p.mutex.Lock()

				resource, err := p.allocation.occupyIP("marked_for_release", "")
				if err != nil {
					p.mutex.Unlock()
					break
				}

				p.allocation.delIP(resource.GetResourceId())

				p.mutex.Unlock()

				log.Infof("Ready to release vpcip %+v, resouce id is %s.", resource.GetIPSet(), resource.GetResourceId())
				_, err = p.store.Delete(resource.GetResourceId())
				if err != nil {
					log.Errorf("Delete vpcip %s from local store error: %s", resource.GetResourceId(), err.Error())
					continue
				}
				err = p.allocator.ReleaseVPCIPResource(resource, true)
				if err != nil {
					log.Errorf("Release vpc ip %s error: %s.", resource.GetResourceId(), err.Error())
					continue
				}
				log.Infof("Release vpc ip %s success.", resource.GetResourceId())
			}
		}
	}

	if poolStatus == WaitingForRelease {
		var toRelease []types.VPCIP
		p.mutex.Lock()

		for i := 0; i < p.allocation.idleCount(); i++ {
			resource, err := p.allocation.occupyIP("marked_for_release", "")
			if err != nil {
				break
			}

			toRelease = append(toRelease, resource)
			p.allocation.delIP(resource.GetResourceId())
		}
		p.mutex.Unlock()

		for _, vpcip := range toRelease {
			log.Infof("Ready to release vpcip %+v, resouce id is %s.", vpcip.GetIPSet(), vpcip.GetResourceId())
			_, err := p.store.Delete(vpcip.GetResourceId())
			if err != nil {
				log.Errorf("Delete vpcip %s from local store error: %s", vpcip.GetResourceId(), err.Error())
			}
			err = p.allocator.ReleaseVPCIPResource(vpcip, true)
			if err != nil {
				log.Errorf("Release vpc ip %s error: %s.", vpcip.GetResourceId(), err.Error())
				continue
			}

			log.Infof("Release vpc ip %s success.", vpcip.GetResourceId())
		}

	}

	p.mutex.Lock()
	idleCount := p.allocation.idleCount()
	usedCount = p.allocation.usedCount()
	totalCount = p.allocation.totalCount()

	log.Infof("Reconciled pool %s, total count %d, idle count %d, usedCount %d", p.name, totalCount, idleCount, usedCount)
	p.mutex.Unlock()

}

func calculateNeededOrReleaseIPs(availableIPs, usedIPs, preAllocate, minAllocate, maxAllocate, maxAboveWatermark int) (neededIPs int) {
	neededIPs = preAllocate - (availableIPs - usedIPs)
	if minAllocate > 0 {
		if neededIPs < minAllocate-availableIPs {
			neededIPs = minAllocate - availableIPs
		}
	}

	if maxAboveWatermark > 0 {
		if usedIPs <= maxAboveWatermark-preAllocate {
			neededIPs = maxAboveWatermark - availableIPs
		} else {
			neededIPs = usedIPs + preAllocate - availableIPs
		}
	}

	// If maxAllocate is set (> 0) and neededIPs is higher than the
	// maxAllocate value, we only return the amount of IPs that can
	// still be allocated
	if maxAllocate > 0 && (availableIPs+neededIPs) > maxAllocate {
		neededIPs = maxAllocate - availableIPs
	}
	return
}

func (p *pool) preReconcile() (bool, PoolConfig, PoolStatus) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.reconcileStatus {
		return true, PoolConfig{}, p.status
	}
	p.reconcileStatus = true
	return false, p.config, p.status
}

func (p *pool) reconcileEnd() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.reconcileStatus = false
}
