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

package daemon

import (
	"context"
	"errors"
	"fmt"
	"github.com/easystack/raptor/pkg/allocator"
	"github.com/easystack/raptor/pkg/storage/bolt"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/vishvananda/netlink"
	"os"
	"sync"
	"time"

	"github.com/easystack/raptor/pkg/k8s"
	raptorv1Beta "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	"github.com/easystack/raptor/pkg/pool"
	"github.com/easystack/raptor/pkg/storage"
	"github.com/easystack/raptor/pkg/types"
)

// VPCResourceManager manages VPC resources such as IP addresses and network cards.
type VPCResourceManager struct {
	nodeIP                string
	nodeName              string // Name of the node
	instanceId            string // Instance ID
	trunkSubnetId         string
	pools                 map[string]pool.PodNetworkPool     // Map of pools for pod networks
	k8sService            k8s.Service                        // Kubernetes service interface
	namespace2poolMapping namespace2poolMap                  // Mapping from namespace to pool
	mutex                 sync.Mutex                         // Mutex for synchronizing access
	networkCardStorage    storage.Storage[types.NetworkCard] // Storage for network cards
	poolStorage           storage.Storage[types.IPPool]      // Storage for ipPool
	ipStorageCreator      types.IpStorageCreator             // Creator for IP storage
	ipStorageKeeper       map[string]storage.Storage[types.VPCIP]
	ipStorageFinalizer    types.IpStorageFinalizer
	allocator             allocator.Allocator // Allocator interface for network resources
}

// newVPCResourceManager creates a new VPCResourceManager instance.
func newVPCResourceManager(
	service k8s.Service,
	nodeIP string,
	nodeName string,
	networkCardStorage storage.Storage[types.NetworkCard],
	poolStorage storage.Storage[types.IPPool],
	trunkSubnetId string,
	ipStorageCreator types.IpStorageCreator,
	ipStorageFinalizer types.IpStorageFinalizer,
	allocator allocator.Allocator,
) *VPCResourceManager {
	m := &VPCResourceManager{
		nodeIP:                nodeIP,
		nodeName:              nodeName,
		pools:                 map[string]pool.PodNetworkPool{},
		k8sService:            service,
		ipStorageCreator:      ipStorageCreator,
		ipStorageKeeper:       map[string]storage.Storage[types.VPCIP]{},
		ipStorageFinalizer:    ipStorageFinalizer,
		poolStorage:           poolStorage,
		trunkSubnetId:         trunkSubnetId,
		networkCardStorage:    networkCardStorage,
		allocator:             allocator,
		namespace2poolMapping: newMapping(),
	}

	return m
}

func (m *VPCResourceManager) Start(ctx context.Context, recordList []*types.PodRecord) error {
	if _, err := os.Stat(types.InstanceIdFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read instance id file error: %s", err.Error())
	} else if os.IsNotExist(err) {
		instanceInfo, err := m.allocator.AcquireInstanceInfo()
		if err != nil {
			return fmt.Errorf("error acquire instance info: %s", err.Error())
		}

		for _, card := range instanceInfo.GetNetworkCards() {
			networkCard := types.TranslateNetworkCard(card)
			owner := networkCard.GetSubnetId()

			if networkCard.GetIPSet().IPv4.String() == m.nodeIP {
				continue
			}

			if networkCard.GetTrunkId() != "" || networkCard.GetSubnetId() == m.trunkSubnetId {
				owner = types.TrunkNetworkCard
			}
			err := m.networkCardStorage.Put(owner, networkCard)
			if err != nil {
				return fmt.Errorf("put networkcard %s to storage error: %s", err.Error())
			}

			for _, ip := range card.VPCIPs {
				var poolStorage storage.Storage[types.VPCIP]
				var has bool

				vpcIP := types.TranslateVPCIP(ip, networkCard)
				if poolStorage, has = m.ipStorageKeeper[ip.GetSubnetId()]; !has {
					podNetwork, err := m.k8sService.GetRaptorPodNetworkBySubnetId(context.TODO(), vpcIP.GetSubnetId())
					if err != nil {
						return fmt.Errorf("get pod network error: %s,subnet id: %s", err.Error(), vpcIP.GetSubnetId())
					}
					poolStorage, err = m.ipStorageCreator(vpcIP.GetSubnetId(), types.IPPool{
						PoolName:    podNetwork.Name,
						NetworkID:   podNetwork.Status.NetworkId,
						SubnetID:    podNetwork.Spec.SubnetId,
						TrunkMode:   networkCard.GetTrunkId() != "",
						GatewayIPv4: podNetwork.Status.GatewayIP.IPv4,
						GatewayIPv6: podNetwork.Status.GatewayIP.IPv6,
						// TODO support IPv6
						SubnetCidr: podNetwork.Spec.CIDR,
					})
					if err != nil {
						return fmt.Errorf("create pool storage %s error: %s", vpcIP.GetPool(), err.Error())
					}
					m.ipStorageKeeper[ip.GetSubnetId()] = poolStorage
				}

				err = poolStorage.Put(vpcIP.GetResourceId(), vpcIP)
				if err != nil {
					return fmt.Errorf("put vpcIP %s to storage error: %s", vpcIP.GetResourceId(), err.Error())
				}
				log.Infof("Put vpc ip %s to storage success, ip address is %+v, pool is %s.", vpcIP.GetResourceId(), vpcIP.GetIPSet(), vpcIP.GetPool())
			}
		}

		m.instanceId = instanceInfo.GetInstanceId()
		log.Infof("Acquire instance info success, instanceId is %s", m.instanceId)
		err = os.WriteFile(types.InstanceIdFilePath, []byte(m.instanceId), 0600)
		if err != nil {
			return fmt.Errorf("write instance id to file %s error: %s", types.InstanceIdFilePath, err.Error())
		}
	} else {
		instanceIdByte, err := os.ReadFile(types.InstanceIdFilePath)
		if err != nil {
			return fmt.Errorf("read instanceId file error: %s", err.Error())
		}
		m.instanceId = string(instanceIdByte)
		log.Infof("Read instance id success, instanceId is %s.", m.instanceId)
	}

	ipPools := m.poolStorage.List()

	pool2Record := map[string][]*types.PodRecord{}

	for i, _ := range recordList {
		record := recordList[i]
		pool2Record[record.SubnetId] = append(pool2Record[record.SubnetId], record)
	}

	for _, ipPool := range ipPools {
		ipPool := ipPool.Value
		if _, ok := m.ipStorageKeeper[ipPool.SubnetID]; !ok {
			var err error
			m.ipStorageKeeper[ipPool.SubnetID], err = m.ipStorageCreator(ipPool.SubnetID, ipPool)
			if err != nil {
				return fmt.Errorf("create ip storage error: %s", err.Error())
			}
		}

		storageKey := ipPool.SubnetID
		if ipPool.TrunkMode {
			storageKey = types.TrunkNetworkCard
		}

		networkCard, err := m.networkCardStorage.Get(storageKey)
		if err != nil {
			log.Fatalf("Get networkcard error: %s", err.Error())
		}

		m.pools[ipPool.SubnetID] = pool.NewPodNetworkPool(ctx, ipPool.PoolName, ipPool.SubnetID, m.allocator, networkCard, m.ipStorageKeeper[ipPool.SubnetID], pool2Record[ipPool.SubnetID], m.k8sService)
	}

	go m.reconcileLoop(ctx)
	go m.networkCardArgsKeeperLoop(ctx)

	log.Infof("VPC resource manager started.")
	return nil
}

// AllocateIP allocates an IP address for a pod.
func (m *VPCResourceManager) AllocateIP(ctx *types.PodAllocateContext) (types.VPCIP, *raptorv1Beta.RaptorPodNetwork, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Determine if a static IP is needed for the pod.
	staticMode, err := m.k8sService.GetIfPodStaticIPNeeded(ctx.Context, ctx.Namespace, ctx.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("judge if pod static ip needed failed, error is: %s", err.Error())
	}

	ctx.Pool, err = m.k8sService.GetIfPodSpecificPoolNeeded(ctx.Context, ctx.Namespace, ctx.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine if pod specific pool needed, error is %s", err)
	}

	var cr *raptorv1Beta.RaptorStaticIP
	var targetPool pool.PodNetworkPool

	if staticMode {
		log.Infof("Pod %s/%s mode is staticMode.", ctx.Namespace, ctx.Name)

		// Get or create a static IP resource.
		cr, err = m.k8sService.GetOrCreateStaticIPCR(ctx.Context, ctx.Namespace, ctx.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("get or create static ip resource error: %s", err.Error())
		}
		if cr.Spec.ResourceId != "" && cr.Spec.Pool != "" {
			ctx.Prefer = cr.Spec.ResourceId
			ctx.Pool = cr.Spec.Pool
		}
	}

	if ctx.Pool != "" {
		// Check if the specific pool exists.
		exist := false
		for _, networkPool := range m.pools {
			if networkPool.Name() == ctx.Pool {
				targetPool = networkPool
				exist = true
				break
			}
		}
		if !exist {
			return nil, nil, fmt.Errorf("specific pool %s not exist on node", ctx.Pool)
		}
	}

	owner := fmt.Sprintf("%s/%s", ctx.Namespace, ctx.Name)

	if targetPool == nil {
		// Find a suitable pool in the namespace.
		namespacePool := m.namespace2poolMapping.getNamespacePool(ctx.Namespace)

		var maxIdleCount int
		var candidateSubnet string

		for _, p := range namespacePool {
			if networkPool, exist := m.pools[p.SubnetID]; exist {
				if status := networkPool.Status(); status.IsActive() && status.IdleCount > maxIdleCount {
					candidateSubnet = p.SubnetID
					maxIdleCount = status.IdleCount
				}
			}
		}

		if maxIdleCount == 0 {
			log.Infof("No pool avilable for namespace %s.", ctx.Namespace)
			return nil, nil, fmt.Errorf("no pool available for namespace %s", ctx.Namespace)
		}

		targetPool = m.pools[candidateSubnet]
	}

	// Allocate an IP address from the target pool.
	vpcIP, err := targetPool.Allocate(ctx.Prefer, owner, staticMode)
	if err != nil {
		return nil, nil, fmt.Errorf("allocate ip failed, error is %s", err.Error())
	}

	// Get the corresponding RaptorPodNetwork resource.
	networkCr, err := m.k8sService.GetRaptorPodNetwork(context.TODO(), vpcIP.GetPool())
	if err != nil {
		return nil, nil, fmt.Errorf("get raptor pod network error: %s", err.Error())
	}

	if staticMode {
		cr.Spec.ResourceId = vpcIP.GetResourceId()
		cr.Spec.Pool = vpcIP.GetPool()
		cr.Spec.IPV4 = vpcIP.GetIPSet().IPv4.String()
		err := m.k8sService.CreateOrUpdateStaticIPCR(context.TODO(), ctx.Namespace, cr)
		if err != nil {
			return nil, nil, err
		}
	}

	return vpcIP, networkCr, nil
}

// ReleaseIP releases an IP address for a pod.
func (m *VPCResourceManager) ReleaseIP(ctx *types.PodReleaseContext) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Determine if a static IP is needed for the pod.
	staticMode, err := m.k8sService.GetIfPodStaticIPNeeded(ctx.Context, ctx.Namespace, ctx.Name)
	if err != nil {
		return fmt.Errorf("judge if pod static ip needed failed, error is: %s", err.Error())
	}

	// Release the IP address from the appropriate pool.
	if networkPool, ok := m.pools[ctx.SubnetId]; ok {
		err := networkPool.Release(ctx.ResourceId, staticMode)
		if err != nil {
			return fmt.Errorf("release resource error: %s", err.Error())
		}
	} else {
		return fmt.Errorf("pool %s not found on node, can't release", ctx.Pool)
	}

	if staticMode {
		ipcr, err := m.k8sService.GetOrCreateStaticIPCR(context.TODO(), ctx.Namespace, ctx.Name)
		if err != nil {
			return fmt.Errorf("get static ip cr error: %s", err)
		}

		ipcr.Spec.NodeName = ""
		err = m.k8sService.CreateOrUpdateStaticIPCR(context.TODO(), ctx.Namespace, ipcr)
		if err != nil {
			return fmt.Errorf("failed to update static ip CR, error: %s", err)
		}
	}

	return nil
}

// reconcileLoop starts a loop to periodically reconcile VPC resources.
func (m *VPCResourceManager) reconcileLoop(ctx context.Context) {
	log.Infof("Start vpc resource reconcile loop")
	m.doReconcile(ctx)

	tk := time.Tick(30 * time.Second)
	for {
		select {
		case <-tk:
			m.doReconcile(ctx)
		case <-ctx.Done():
			goto stop
		}
	}
stop:
	log.Infof("Stopped vpc resource reconcile loop")
}

// doReconcile performs the reconciliation of VPC resources.
func (m *VPCResourceManager) doReconcile(ctx context.Context) {

	log.Infof("Do reconcile for VPC resource.")
	newNamespace2PoolData := map[string][]types.IPPool{}
	podNetworkCrs, err := m.k8sService.ListRaptorPodNetworks(context.TODO())
	if err != nil {
		log.Errorf("List raptorPodNetworks error: %s", err)
	}

	for _, cr := range podNetworkCrs {
		if cr.Spec.IsClusterInstanceSubnet {
			continue
		}

		ipPool := types.IPPool{
			PoolName:    cr.Name,
			NetworkID:   cr.Status.NetworkId,
			SubnetID:    cr.Spec.SubnetId,
			TrunkMode:   cr.Spec.TrunkMode,
			GatewayIPv4: cr.Status.GatewayIP.IPv4,
			GatewayIPv6: cr.Status.GatewayIP.IPv6,
			SubnetCidr:  cr.Spec.CIDR,
		}

		for _, namespace := range cr.Spec.SelectedNameSpace {
			newNamespace2PoolData[namespace] = append(newNamespace2PoolData[namespace], ipPool)
		}

		cfg := pool.PoolConfig{
			MinAllocate: cr.Spec.MinAllocate,
			MaxAllocate: cr.Spec.MaxAllocate,
			PreAllocate: cr.Spec.PreAllocate,
			Watermark:   cr.Spec.Watermark,
			TrunkMode:   cr.Spec.TrunkMode,
		}
		var podNetwork pool.PodNetworkPool

		if len(cr.Spec.SelectedNodes) == 0 {
			// Handle pools with no selected nodes.
			if _, exist := m.pools[cr.Spec.SubnetId]; exist && !m.pools[cr.Spec.SubnetId].Status().IsActive() {
				cfg.PoolStatus = pool.WaitingForRelease
			}
		}

		for idx, node := range cr.Spec.SelectedNodes {
			if node == m.nodeName {
				// Handle pools for the current node.
				if _, exist := m.pools[cr.Spec.SubnetId]; !exist {

					store, err := m.ipStorageCreator(cr.Spec.SubnetId, ipPool)
					if err != nil {
						log.Fatalf("Create storage for pool error: %s", err)
					}

					var networkCard types.NetworkCard
					var cardOwner string
					var networkCardSubnetId string

					if cr.Spec.TrunkMode {
						cardOwner = types.TrunkNetworkCard
						networkCardSubnetId = m.trunkSubnetId
					} else {
						cardOwner = cr.Spec.SubnetId
						networkCardSubnetId = cr.Spec.SubnetId
					}
					networkCard, err = m.networkCardStorage.Get(cardOwner)
					if err != nil && !errors.Is(err, bolt.KeyNotFoundErr{}) {
						log.Fatalf("Get networkcard error: %s", err.Error())
					}

					if networkCard == nil {
						// Apply for a new network card.
						networkCard, err = m.allocator.ApplyForNetworkCard(networkCardSubnetId, m.instanceId, cr.Spec.TrunkMode)
						if err != nil {
							log.Errorf("Apply for network card error: %s.", err.Error())
							continue
						}
						log.Infof("Apply network card for pool %s successfully.", ipPool.PoolName)

						err = m.networkCardStorage.Put(cardOwner, networkCard)
						if err != nil {
							// Let daemon crash when putting the network card to store failed.
							log.Fatalf("Put network card to store error %s.", err.Error())
						}
					}

					err = utils.SetUpNewNetworkCard(networkCard, ipPool)
					if err != nil {
						log.Fatalf("Set up networkCard error: %s.", err.Error())
					}

					if cr.Spec.TrunkMode {
						err = m.k8sService.PatchTrunkInfoToNode(context.TODO(), types.TrunkInfo{TrunkId: networkCard.GetTrunkId(), TrunkParentId: networkCard.GetResourceId()})
						if err != nil {
							log.Infof("Failed to patch trunk info to node, error: %s", err)
						}
					}

					m.pools[cr.Spec.SubnetId] = pool.NewPodNetworkPool(ctx, cr.Name, cr.Spec.SubnetId, m.allocator, networkCard, store, nil, m.k8sService)
				}

				cfg.PoolStatus = pool.Active
				podNetwork = m.pools[cr.Spec.SubnetId]
				break
			}

			if idx == len(cr.Spec.SelectedNodes)-1 {
				// Handle pools that are no longer selected.
				if _, exist := m.pools[cr.Spec.SubnetId]; exist && m.pools[cr.Spec.SubnetId].Status().IsActive() {
					podNetwork = m.pools[cr.Spec.SubnetId]
					cfg.PoolStatus = pool.WaitingForRelease
				}
			}
		}

		if podNetwork != nil {
			podNetwork.SetConfig(cfg)
		}

		for subnetId, networkPool := range m.pools {
			status := networkPool.Status()
			err := m.k8sService.PatchPodNetworkCondition(int64(status.IdleCount), int64(status.TotalCount), int64(status.AllocatedCount),
				status.SubnetId, status.PoolStatus == pool.Terminated)
			if err != nil {
				log.Errorf("Patch pod network condition error: %s.", err)
				continue
			}
			if status.PoolStatus == pool.Terminated {
				if !status.TrunkMode {
					networkCard, err := m.networkCardStorage.Delete(subnetId)
					if err != nil {
						log.Errorf("Delete network card for subnet %s error: %s.", subnetId, err.Error())
						continue
					}
					err = m.allocator.ReleaseNetworkCard(networkCard.GetResourceId())
					if err != nil {
						log.Errorf("Release network card %s error: %s.", networkCard.GetResourceId(), err.Error())
						continue
					}
				}
				delete(m.pools, subnetId)
				err = m.ipStorageFinalizer(subnetId)
				if err != nil {
					log.Errorf("Do storage finalizer for pool %s error: %s.", networkPool.Name(), err.Error())
				}
			}
		}
	}

	// Update the namespace to pool mapping with new data.
	m.namespace2poolMapping.update(newNamespace2PoolData)

	log.Infof("Reconciled VPC resources.")
	// TODO according selected labels to create pool

	return
}

func (m *VPCResourceManager) networkCardArgsKeeperLoop(ctx context.Context) {
	log.Infof("Started networkCard args Keeper job.")
	tk := time.Tick(1 * time.Minute)
	for {
		select {
		case <-tk:
			m.maintainNetworkCards()
		case <-ctx.Done():
			goto stop
		}
	}
stop:
	log.Infof("Stopped networkCard args Keeper job.")
}

func (m *VPCResourceManager) maintainNetworkCards() {
	networkCards := m.networkCardStorage.List()
	linkList, err := netlink.LinkList()
	if err != nil {
		log.Errorf("Failed to list link, error is %s.", err.Error())
		return
	}
	mac2Link := map[string]netlink.Link{}
	for _, link := range linkList {
		mac2Link[link.Attrs().HardwareAddr.String()] = link
	}

	for _, card := range networkCards {
		card := card.Value
		cr, err := m.k8sService.GetRaptorPodNetworkBySubnetId(context.TODO(), card.GetSubnetId())
		if err != nil {
			log.Errorf("Error getting raptor pod network by subnet id %s.", err.Error())
			continue
		}

		ipPool := types.IPPool{
			PoolName:    cr.Name,
			NetworkID:   cr.Status.NetworkId,
			SubnetID:    cr.Spec.SubnetId,
			TrunkMode:   cr.Spec.TrunkMode,
			GatewayIPv4: cr.Status.GatewayIP.IPv4,
			GatewayIPv6: cr.Status.GatewayIP.IPv6,
			SubnetCidr:  cr.Spec.CIDR,
		}

		err = utils.SetUpNewNetworkCard(card, ipPool)
		if err != nil {
			log.Errorf("Set up network card error: %s.", err.Error())
		}
		//if link, ok := mac2Link[card.GetMacAddress()]; ok {
		//	if card.GetTrunkId() != "" {
		//		addrList, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		//		if err == nil {
		//			for _, addr := range addrList {
		//				err := netlink.AddrDel(link, &addr)
		//				if err != nil {
		//					log.Errorf("Remove addr for link %s error: %s.", link.Attrs().Name, err.Error())
		//				}
		//			}
		//		} else {
		//			log.Errorf("List addr for link error: %s.", link.Attrs().Name)
		//		}
		//	}
		//	if link.Attrs().OperState == netlink.OperDown {
		//		err := netlink.LinkSetUp(link)
		//		if err != nil {
		//			log.Errorf("Set link up for %s error: %s.", link.Attrs().Name, err.Error())
		//		}
		//	}
		//
		//	err := utils.DisableRpFilter(link.Attrs().Name)
		//	if err != nil {
		//		log.Errorf("Disable rp_filter for link %s error: %s.", link.Attrs().Name, err.Error())
		//	}
		//}
	}
}
