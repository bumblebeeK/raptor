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

package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/easystack/raptor/cmd/coordinator/option"
	"github.com/easystack/raptor/pkg/base"
	raptorV1beta "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	raptorClientset "github.com/easystack/raptor/pkg/k8s/generated/clientset/versioned"
	"github.com/easystack/raptor/pkg/k8s/generated/informers/externalversions"
	raptorListerV1beta "github.com/easystack/raptor/pkg/k8s/generated/listers/raptor.io/v1beta1"
	"github.com/easystack/raptor/pkg/provider/openstack"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/easystack/raptor/rpc"
	"github.com/jasonlvhit/gocron"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

var log = base.NewLogWithField("subsys", "coordinator-server")

// Server represent
type Server struct {
	kubeClient             *kubernetes.Clientset
	raptorClient           *raptorClientset.Clientset
	openstackClient        *openstack.Client
	raptorPodNetworkLister raptorListerV1beta.RaptorPodNetworkLister

	rpc.UnimplementedCoordinatorBackendServer

	instanceMap                         *InstanceMap
	subnetsMap                          *SubnetMap
	ip2pidMap                           *Ip2PidMap
	instanceNetworkCardIP2InstanceIDMap *InstanceNetworkCardIP2InstanceIDMap

	apiReady bool

	listenAddr      string
	projectId       string
	defaultSubnetID map[string]struct{}

	mutex       sync.Mutex
	underResync bool
}

// NewCoordinatorServer create the CoordinatorServer.
func NewCoordinatorServer(option *option.ServerOption) (error, *Server) {

	var err error
	config, err := utils.GetConfigFromKube()
	if err != nil {
		return err, nil
	}

	server := &Server{
		instanceMap:                         &InstanceMap{data: map[string]*Instance{}},
		ip2pidMap:                           &Ip2PidMap{data: map[string]string{}},
		subnetsMap:                          &SubnetMap{data: map[string]*rpc.Subnet{}},
		instanceNetworkCardIP2InstanceIDMap: &InstanceNetworkCardIP2InstanceIDMap{data: map[string]string{}},
		listenAddr:                          option.ListenAddress,
	}

	server.openstackClient, err = openstack.NewClient(&option.OpenStackOption)
	if err != nil {
		return err, nil
	}

	server.raptorClient = raptorClientset.NewForConfigOrDie(config)
	server.kubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err, nil
	}

	return nil, server
}

func (c *Server) Start(ctx context.Context) error {
	var err error

	raptorInformer := externalversions.NewSharedInformerFactory(c.raptorClient, 0)
	c.raptorPodNetworkLister = raptorInformer.Raptor().V1beta1().RaptorPodNetworks().Lister()
	raptorInformer.Start(ctx.Done())

	raptorInformer.WaitForCacheSync(ctx.Done())
	log.Infof("all cache synced successfully.")

	c.StartResyncTask(ctx)

	server := grpc.NewServer()
	tcpListener, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on addr %v, error is  %v.", c.listenAddr, err)
	}
	log.Infof("server listening on %v.", tcpListener.Addr())

	rpc.RegisterCoordinatorBackendServer(server, c)

	return server.Serve(tcpListener)
}

func (c *Server) StartResyncTask(ctx context.Context) {
	err := c.resync()
	if err != nil {
		log.Fatalf("failed to resync cluster resources, error is %s.", err)
	}

	log.Infof("resync cluster resources success.")
	job := gocron.Every(1).Minute()

	err = job.Do(func() {
		err = c.resync()
		if err != nil {
			log.Errorf("failed to resync cluster resources, error is %s.", err)
		} else {
			log.Infof("resync cluster resources success.")
		}
	})

	if err != nil {
		log.Fatalf("failed to create resync cluster resource job, error is %s.", err)
	}

	gocron.Start()

	go func() {
		<-ctx.Done()
		gocron.Remove(job)
	}()

}

func (c *Server) isApiReady() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.apiReady
}

func (c *Server) setApiNotReady() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.apiReady = false
}

func (c *Server) setApiReady() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.apiReady = true
}

func (c *Server) isUnderResync() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.underResync
}

func (c *Server) startResync() {
	c.mutex.Lock()
	c.underResync = true
	c.mutex.Unlock()
}

func (c *Server) resyncFinished() {
	c.mutex.Lock()
	c.underResync = false
	c.mutex.Unlock()
}

func (c *Server) resync() error {
	if c.isUnderResync() {
		return nil
	}
	defer c.resyncFinished()

	var err error
	defer c.judgeOpenstackServerReady(err)

	ip2pids := map[string]string{}

	subnets := map[string]*rpc.Subnet{}
	instances := map[string]*rpc.Instance{}
	pool2NetworkCardCount := map[string][]string{}
	defaultNetworkCardIP2InstanceIDMap := map[string]string{}

	err, id2ips := c.openstackClient.GetSubnets(ip2pids, subnets)
	if err != nil {
		return err
	}

	c.subnetsMap.UpdateSubnets(subnets)

	err = c.openstackClient.GetInstances(ip2pids, id2ips, defaultNetworkCardIP2InstanceIDMap, instances)
	if err != nil {
		return err
	}

	c.ip2pidMap.Update(ip2pids)
	c.instanceMap.UpdateInstances(instances)
	c.instanceNetworkCardIP2InstanceIDMap.Update(defaultNetworkCardIP2InstanceIDMap)

	c.MaintainPodNetworkResources(pool2NetworkCardCount)

	return nil
}

func (c *Server) MaintainPodNetworkResources(pool2NetworkCardCount map[string][]string) {
	for _, subnet := range c.subnetsMap.AcquireSubnet() {
		rpn, err := c.raptorPodNetworkLister.Get(subnet.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				network := &raptorV1beta.RaptorPodNetwork{
					ObjectMeta: metav1.ObjectMeta{
						Name: utils.NormalizeCRName(subnet.Name),
					},
					Spec: raptorV1beta.PodNetworkSpec{
						SubnetId: subnet.ID,
						CIDR:     subnet.CIDR.IPv4,
					},
				}

				if subnet.IsDefault {
					network.Spec.IsClusterInstanceSubnet = true
				}

				rpn, err = c.raptorClient.RaptorV1beta1().RaptorPodNetworks().Create(context.TODO(), network, metav1.CreateOptions{})
				if err != nil {
					log.Errorf("failed to create RaptorPodNetwork %s, error is %s", utils.NormalizeCRName(subnet.Name), err)
					continue
				}
			} else {
				log.Errorf("failed to get RaptorPodNetwork %s, error is %s", rpn.Name, err)
				continue
			}
		}

		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			rpn, err := c.raptorPodNetworkLister.Get(subnet.Name)
			if err != nil {
				return err
			}
			r := rpn.DeepCopy()
			r.Status.Active = true
			r.Status.GatewayIP = raptorV1beta.GatewayIP{IPv4: subnet.GatewayIP.IPv4, IPv6: subnet.GatewayIP.IPv6}
			r.Status.AllocationCount = subnet.AllocationCount
			r.Status.AllocatedCount = subnet.AllocatedCount
			r.Status.NetworkId = subnet.NetworkID
			if reflect.DeepEqual(r, rpn) {
				return nil
			}
			_, err = c.raptorClient.RaptorV1beta1().RaptorPodNetworks().UpdateStatus(context.TODO(), r, metav1.UpdateOptions{})
			return err
		})

		if err != nil {
			log.Errorf("update raptorPodNetwork %s failed, error is %s.", rpn.Name, err)
		}

		var finalizers []string
		if len(pool2NetworkCardCount[rpn.Name]) != 0 {
			finalizers = []string{"raptor"}
		} else {
			finalizers = []string{}
		}

		if len(finalizers) != len(rpn.Finalizers) {
			patchData := []map[string]interface{}{
				{
					"op":    "replace",
					"path":  "/metadata/finalizers",
					"value": finalizers,
				},
			}

			patchBytes, _ := json.Marshal(patchData)
			_, err = c.raptorClient.RaptorV1beta1().RaptorPodNetworks().Patch(
				context.TODO(),
				rpn.Name,
				types.JSONPatchType,
				patchBytes,
				metav1.PatchOptions{},
			)
			if err != nil {
				log.Errorf("failed to patch finalizers for raptorpodnetwork %s", rpn.Name)
			}
		}
	}
}

// AcquireInstanceInfo accept acquire instance info from coordinator clients
func (c *Server) AcquireInstanceInfo(ctx context.Context, in *rpc.AcquireInstanceInfoRequest) (*rpc.AcquireInstanceInfoReply, error) {

	instanceID := c.instanceNetworkCardIP2InstanceIDMap.AcquireInstanceID(in.GetNodeIP())
	if instanceID != "" {
		instance := c.instanceMap.AcquireInstance(instanceID)
		instance.InstanceId = instanceID
		return &rpc.AcquireInstanceInfoReply{
			Instance: instance,
		}, nil
	} else {
		return &rpc.AcquireInstanceInfoReply{
			Instance: nil,
		}, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to acquire instance info by ip %s", in.GetNodeIP()))
	}

}

// AllocateIPResource accept allocate eni ip requests from clients
func (c *Server) AllocateIPResource(ctx context.Context, in *rpc.AllocateIPResourceRequest) (*rpc.AllocateIPResourceReply, error) {
	var err error
	var vpcIP *rpc.VPCIP
	subnet := c.subnetsMap.AcquireSubnetById(in.GetSubnetId())
	if subnet == nil {
		return &rpc.AllocateIPResourceReply{}, status.Errorf(codes.Internal, "failed to get subnet %s", in.GetSubnetId())
	}

	if in.GetTrunkId() != "" {
		vpcIP, err = c.openstackClient.AssignSubPortToTrunk(in.GetTrunkId(), subnet.NetworkID, in.GetSubnetId(), in.GetPool(), in.GetResourceId())
	} else {
		vpcIP, err = c.openstackClient.AssignPrivateIPAddresses(in.GetNetworkCardPortId(), in.GetNetworkCardMacAddress(), subnet.NetworkID, in.GetSubnetId(), in.GetPool(), in.GetResourceId())
	}
	c.judgeOpenstackServerReady(err)
	if err != nil {
		return &rpc.AllocateIPResourceReply{}, status.Error(codes.Internal, fmt.Sprintf("failed to allocate pod ip, error is %s", err))
	}

	return &rpc.AllocateIPResourceReply{
		VPCIP: vpcIP,
	}, nil
}

// ReleaseIPResource ReleasePodIP accept release eni ip requests from coordinator clients
func (c *Server) ReleaseIPResource(ctx context.Context, in *rpc.ReleaseIPResourceRequest) (*rpc.ReleasePodIPReply, error) {
	var err error
	if in.GetTrunkId() != "" {
		log.Infof("Unassign sub port for trunk %s", in.GetTrunkId())
		err = c.openstackClient.UnAssignSubPortForTrunk(in.GetResourceId(), in.GetTrunkId(), in.GetDeleteResource())
	} else if in.GetIPSet() != nil {
		err = c.openstackClient.UnAssignPrivateIPAddress(in.GetIPSet(), in.GetMacAddress(), in.GetNetworkCardPortId(), in.GetResourceId(), in.GetDeleteResource())
	} else {
		return &rpc.ReleasePodIPReply{}, status.Error(codes.InvalidArgument, "invalid resource type")
	}

	c.judgeOpenstackServerReady(err)
	if err != nil {
		return &rpc.ReleasePodIPReply{}, status.Errorf(codes.Internal, "failed to relase pod ip, error is %s", err)
	}

	return &rpc.ReleasePodIPReply{}, nil

}

// AllocateNetworkCard accept allocate eni requests from coordinator clients
func (c *Server) AllocateNetworkCard(ctx context.Context, in *rpc.AllocateNetworkCardRequest) (*rpc.AllocateNetworkCardReply, error) {
	subnet := c.subnetsMap.AcquireSubnetById(in.GetSubnetId())
	if subnet == nil {
		return &rpc.AllocateNetworkCardReply{}, status.Error(codes.Internal, "failed to get subnet ")
	}

	networkCard, err := c.openstackClient.CreateNetworkInterface(in.GetInstanceId(), subnet.GetNetworkID(), in.GetSubnetId(), in.GetTrunk())
	defer c.judgeOpenstackServerReady(err)
	if err != nil {
		return &rpc.AllocateNetworkCardReply{}, status.Error(codes.Internal, fmt.Sprintf("failed to allocate network card, error is %s", err))
	}

	err = c.openstackClient.AttachNetworkInterface(in.GetInstanceId(), networkCard.GetID())
	if err != nil {
		return &rpc.AllocateNetworkCardReply{}, status.Error(codes.Internal, fmt.Sprintf("failed to allocate eni, error is %s", err))
	}

	return &rpc.AllocateNetworkCardReply{
		NetworkCard: networkCard,
	}, nil
}

// ReleaseNetworkCard accept release eni requests from coordinator clients
func (c *Server) ReleaseNetworkCard(ctx context.Context, in *rpc.ReleaseNetworkCardRequest) (*rpc.ReleaseNetworkCardReply, error) {
	err := c.openstackClient.DeleteNetworkInterface(in.GetNetworkCardPortId())
	c.judgeOpenstackServerReady(err)
	if err != nil {
		return &rpc.ReleaseNetworkCardReply{}, status.Error(codes.Internal, fmt.Sprintf("failed to relase eni, error is %s", err))
	}
	return &rpc.ReleaseNetworkCardReply{}, nil
}

// TransferPodIP accept transfer podIP requests from coordinator clients
func (c *Server) TransferPodIP(ctx context.Context, in *rpc.TransferIPResourceRequest) (*rpc.TransferIPResourceReply, error) {
	err := c.openstackClient.TransferPortFromNetworkCardAToAnotherNetworkCardB(in.GetFromNetworkCard(), in.GetToNetworkCard(), in.GetMacAddress(), in.GetVPCIP())
	c.judgeOpenstackServerReady(err)
	if err != nil {
		return &rpc.TransferIPResourceReply{}, status.Error(codes.Internal, fmt.Sprintf("failed to relase pod ip, error is %s", err))
	}
	return &rpc.TransferIPResourceReply{}, nil
}

func (c *Server) AcquireServerStress(context.Context, *rpc.AcquireServerStressRequest) (*rpc.AcquireServerStressReply, error) {
	return &rpc.AcquireServerStressReply{
		ApiReady: c.isApiReady(),
	}, nil
}

func (c *Server) judgeOpenstackServerReady(err error) {
	if err != nil && strings.Contains(err.Error(), "timeout") {
		c.setApiNotReady()
	} else {
		c.setApiReady()
	}
}
