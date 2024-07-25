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

package allocator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/rpc"
	"google.golang.org/grpc"
)

var log = base.NewLogWithField("sub_sys", "allocator")

// Allocator defines the interface for network resource allocation and management.
type Allocator interface {
	// ApplyForNetworkCard applies for a network card resource.
	ApplyForNetworkCard(subnetId string, instanceId string, isTrunk bool) (types.NetworkCard, error)

	// ApplyForVPCIPResource applies for a VPC IP resource.
	ApplyForVPCIPResource(card types.NetworkCard, subnetId, pool, resourceId string) (types.VPCIP, error)

	// ReleaseVPCIPResource releases a VPC IP resource.
	ReleaseVPCIPResource(vpcIP types.VPCIP, deleteResource bool) error

	// ReleaseNetworkCard releases a network card resource.
	ReleaseNetworkCard(networkCardID string) error

	// AcquireInstanceInfo acquires information about the instance.
	AcquireInstanceInfo() (*rpc.Instance, error)

	// TransferIP transfers an IP from one network card to another.
	TransferIP(fromNetworkCard, toNetworkCard string, macAddress string, podIP *rpc.VPCIP) error

	// JudgeCalleeReady checks if the callee is ready.
	JudgeCalleeReady() bool
}

// CoordinatorAllocator implements the Allocator interface for coordinating network resources.
type CoordinatorAllocator struct {
	nodeIP            string
	apiReady          bool
	mutex             sync.RWMutex
	addr              string
	coordinatorClient rpc.CoordinatorBackendClient
	inSubPortAllocate bool
}

// NewCoordinatorAllocator creates a new instance of CoordinatorAllocator.
func NewCoordinatorAllocator(ctx context.Context, nodeIP string, addr string) Allocator {
	c := &CoordinatorAllocator{
		nodeIP: nodeIP,
		addr:   addr,
	}
	return c
}

// session represents a gRPC session.
type session struct {
	*grpc.ClientConn
	rpc.CoordinatorBackendClient
}

// JudgeCalleeReady checks if the callee is ready.
func (c *CoordinatorAllocator) JudgeCalleeReady() bool {
	return true
}

// dial establishes a gRPC connection to the coordinator.
func (c *CoordinatorAllocator) dial() (*session, error) {
	conn, err := grpc.Dial(c.addr, grpc.WithInsecure(), grpc.WithTimeout(time.Second*20))
	if err != nil {
		return nil, fmt.Errorf("dial coordinator %q: %v", c.addr, err)
	}
	s := &session{
		ClientConn:               conn,
		CoordinatorBackendClient: rpc.NewCoordinatorBackendClient(conn),
	}
	return s, nil
}

// close closes the gRPC session.
func close(s *session) error {
	if s.ClientConn == nil {
		return nil
	}
	return s.Close()
}

// ApplyForNetworkCard applies for a network card resource.
func (c *CoordinatorAllocator) ApplyForNetworkCard(subnetId string, instanceId string, isTrunk bool) (types.NetworkCard, error) {
	req := &rpc.AllocateNetworkCardRequest{
		InstanceId: instanceId,
		SubnetId:   subnetId,
		Trunk:      isTrunk,
	}
	session, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer close(session)
	reply, err := session.AllocateNetworkCard(context.TODO(), req)
	if err != nil {
		return nil, err
	}
	networkCard := reply.GetNetworkCard()
	return types.TranslateNetworkCard(networkCard), err
}

// ApplyForVPCIPResource applies for a VPC IP resource.
func (c *CoordinatorAllocator) ApplyForVPCIPResource(card types.NetworkCard, subnetId string, pool, resourceId string) (types.VPCIP, error) {
	if card.GetTrunkId() != "" {
		if !c.allocateSubPortStart() {
			return nil, fmt.Errorf("other pool is applying for vpc ip")
		}
	}
	defer c.allocateSubPortEnd()
	req := &rpc.AllocateIPResourceRequest{
		SubnetId:              subnetId,
		Pool:                  pool,
		TrunkId:               card.GetTrunkId(),
		NetworkCardId:         card.GetResourceId(),
		NetworkCardMacAddress: card.GetMacAddress(),
		ResourceId:            resourceId,
	}
	session, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	reply, err := session.AllocateIPResource(context.TODO(), req)
	if err != nil {
		return nil, err
	}
	return types.TranslateVPCIP(reply.GetVPCIP(), card), nil
}

// ReleaseVPCIPResource releases a VPC IP resource.
func (c *CoordinatorAllocator) ReleaseVPCIPResource(resource types.VPCIP, deleteResource bool) error {
	req := &rpc.ReleaseIPResourceRequest{
		ResourceId:    resource.GetResourceId(),
		NetworkCardId: resource.GetNetworkCardId(),
		TrunkId:       resource.GetTrunkId(),
		IPSet: &rpc.IPSet{
			IPv4: resource.GetIPSet().IPv4.String(),
			IPv6: resource.GetIPSet().IPv6.String(),
		},
		Vid:            uint32(resource.GetVid()),
		MacAddress:     resource.GetMacAddress(),
		DeleteResource: deleteResource,
	}
	session, err := c.dial()
	if err != nil {
		return err
	}
	defer close(session)
	_, err = session.ReleaseIPResource(context.TODO(), req)
	return err
}

// ReleaseNetworkCard releases a network card resource.
func (c *CoordinatorAllocator) ReleaseNetworkCard(networkCardID string) error {
	req := &rpc.ReleaseNetworkCardRequest{
		NetworkCardId: networkCardID,
	}
	session, err := c.dial()
	if err != nil {
		return err
	}
	defer close(session)
	_, err = session.ReleaseNetworkCard(context.TODO(), req)
	return err
}

// AcquireInstanceInfo acquires information about the instance.
func (c *CoordinatorAllocator) AcquireInstanceInfo() (*rpc.Instance, error) {
	req := &rpc.AcquireInstanceInfoRequest{
		NodeIP: c.nodeIP,
	}
	session, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer close(session)
	reply, err := session.AcquireInstanceInfo(context.TODO(), req)
	if err != nil {
		return nil, err
	}
	return reply.GetInstance(), nil
}

// TransferIP transfers an IP from one network card to another.
func (c *CoordinatorAllocator) TransferIP(fromNetworkCard, toNetworkCard string, macAddress string, vpcIP *rpc.VPCIP) error {
	req := &rpc.TransferIPResourceRequest{
		VPCIP:           vpcIP,
		FromNetworkCard: fromNetworkCard,
		ToNetworkCard:   toNetworkCard,
		MacAddress:      macAddress,
	}
	_, err := c.coordinatorClient.TransferIPResource(context.TODO(), req)
	if err != nil {
		return fmt.Errorf("failed to transfer ip, error is %s", err)
	}
	return nil
}

// allocateSubPortStart indicates the start of a sub-port allocation.
func (c *CoordinatorAllocator) allocateSubPortStart() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.inSubPortAllocate {
		return false
	}
	c.inSubPortAllocate = true
	return true
}

// allocateSubPortEnd indicates the end of a sub-port allocation.
func (c *CoordinatorAllocator) allocateSubPortEnd() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.inSubPortAllocate = false
}
