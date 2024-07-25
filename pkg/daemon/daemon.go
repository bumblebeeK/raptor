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
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/easystack/raptor/cmd/daemon/option"
	"github.com/easystack/raptor/pkg/allocator"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/k8s"
	"github.com/easystack/raptor/pkg/provider/openstack"
	"github.com/easystack/raptor/pkg/storage"
	"github.com/easystack/raptor/pkg/storage/bolt"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/pkg/utils"
	rRpc "github.com/easystack/raptor/rpc"
	"github.com/gorilla/mux"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gRpcStatus "google.golang.org/grpc/status"
	k8sErr "k8s.io/apimachinery/pkg/api/errors"
)

var log = base.NewLogWithField("sub_sys", "daemon")

// Daemon struct holds the necessary components and configurations for the daemon.
type Daemon struct {
	networkMode        string
	nodeName           string
	nodeIP             string
	option             *option.DaemonOption
	k8sManager         k8s.Service
	instanceMetaGetter openstack.InstanceMetadataGetter
	vpcResourceManager *VPCResourceManager
	recordStorage      storage.Storage[types.PodRecord]
	networkStorage     storage.Storage[types.NetworkCard]
	poolStorage        storage.Storage[types.IPPool]
	engine             *bolt.BoltEngine

	rRpc.UnimplementedRaptorBackendServer
}

// NewDaemon initializes a new Daemon instance.
func NewDaemon(ctx context.Context, option *option.DaemonOption) *Daemon {
	var err error
	d := &Daemon{
		option: option,
	}

	// Fetch the node name from the environment variable.
	if d.nodeName = os.Getenv(utils.EnvNodeNameSpec); d.nodeName == "" {
		log.Fatalf("No node name specified.")
	}

	// Fetch the node IP from the environment variable.
	if d.nodeIP = os.Getenv(utils.EnvNodeIPSpec); d.nodeIP == "" {
		log.Fatalf("No node IP found in env.")
	}

	// Create a new raptor client.
	raptorClient, err := utils.GetRaptorClient()
	if err != nil {
		log.Fatalf("Create raptor client error: %s", err.Error())
	}

	// Create a new k8s client.
	k8sClient, err := utils.GetK8sClient()
	if err != nil {
		log.Fatalf("Create k8s client error: %s", err.Error())
	}

	// Initialize the k8s manager service.
	d.k8sManager, err = k8s.NewK8sService(ctx, d.nodeName, k8sClient, raptorClient)
	if err != nil {
		log.Fatalf("Init k8s service error: %s.", err.Error())
	}

	d.engine, err = initBoltEngine()
	if err != nil {
		log.Fatalf("Create bolt engine error: %s.", err.Error())
	}

	// Initialize the record storage for Pod records.
	d.recordStorage, err = bolt.NewStorage[types.PodRecord, types.PodRecord]("record", d.engine)
	if err != nil {
		log.Fatalf("Create pod record storage error: %s.", err.Error())
	}

	// Initialize the network card storage.
	d.networkStorage, err = bolt.NewStorage[types.NetworkCard, types.NetworkCardImpl]("networkCard", d.engine)
	if err != nil {
		log.Fatalf("Create networkcard storage error: %s.", err.Error())
	}

	// Initialize the IP pool storage.
	d.poolStorage, err = bolt.NewStorage[types.IPPool, types.IPPool]("ipPool", d.engine)

	// Create a new allocator.
	alloc := allocator.NewCoordinatorAllocator(ctx, d.nodeIP, option.CoordinatorServerAddress)

	// Initialize the VPC resource manager.
	d.vpcResourceManager = newVPCResourceManager(
		d.k8sManager,
		d.nodeIP,
		d.nodeName,
		d.networkStorage,
		d.poolStorage,
		option.TrunkSubnetId,
		func(subnetId string, ipPool types.IPPool) (storage.Storage[types.VPCIP], error) {
			err := d.poolStorage.Put(subnetId, ipPool)
			if err != nil {
				return nil, err
			}
			return bolt.NewStorage[types.VPCIP, types.VPCIPImpl](subnetId, d.engine)
		},
		func(subnetId string) error {
			_, err = d.poolStorage.Delete(subnetId)
			return err
		},
		alloc,
	)

	return d
}

// Start runs the daemon, initializing necessary components and starting the gRPC server.
func (d *Daemon) Start(ctx context.Context) {
	defer d.engine.Close()

	// Restore endpoints from storage.
	recordList, err := d.RestoreEndpoint()
	if err != nil {
		log.Fatalf("Restore end point error: %s", err)
	}

	// Start the VPC resource manager.
	err = d.vpcResourceManager.Start(ctx, recordList)
	if err != nil {
		log.Fatalf("VPC resource manager started error: %s", err.Error())
	}

	// Create directory for the gRPC socket.
	if err := os.MkdirAll(filepath.Dir(types.DefaultSocketPath), 0700); err != nil {
		log.Fatalf("Make dir for raptor socket err: %s", err.Error())
	}
	// Remove old socket file if it exists.
	if err := os.Remove(types.DefaultSocketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Remove old socket file error: %s", err.Error())
	}

	// Start listening on the UNIX socket.
	l, err := net.Listen("unix", types.DefaultSocketPath)
	if err != nil {
		log.Fatalf("Listen addr error: %s", err)
	}

	// Start healthZ and pprof server.
	go d.startHealthZAndPProfServer(ctx)

	// Create a new gRPC server for cni binary tp call.
	grpcServer := grpc.NewServer()
	rRpc.RegisterRaptorBackendServer(grpcServer, d)
	// Start serving gRPC requests.
	err = grpcServer.Serve(l)
	if err != nil {
		log.Fatalf("Serve grpc error: %v", err)
	}
}

// CreateEndpoint handles requests to create a new endpoint.
func (d *Daemon) CreateEndpoint(ctx context.Context, request *rRpc.CreateEndpointRequest) (*rRpc.CreateEndpointResponse, error) {

	allocateCtx := &types.PodAllocateContext{
		Context:   ctx,
		Name:      request.K8SPodName,
		Namespace: request.K8SPodNamespace,
		SandBoxId: request.K8SPodInfraContainerId,
	}

	owner := fmt.Sprintf("%s/%s", request.GetK8SPodNamespace(), request.GetK8SPodName())
	log.Infof("Pod %s request an ip.", owner)

	// Allocate IP for the Pod.
	vpcIP, podNetwork, err := d.vpcResourceManager.AllocateIP(allocateCtx)
	if err != nil {
		return &rRpc.CreateEndpointResponse{}, fmt.Errorf("allocate ip error: %s", err.Error())
	}

	// Create a record for the Pod.
	record := types.PodRecord{
		Pool:       vpcIP.GetPool(),
		ResourceId: vpcIP.GetResourceId(),
		SubnetId:   vpcIP.GetSubnetId(),
		Name:       request.K8SPodName,
		Namespace:  request.K8SPodNamespace,
		Trunk:      vpcIP.GetTrunkId() != "",
		SandBoxId:  request.K8SPodInfraContainerId,
	}

	// Store the Pod record.
	err = d.recordStorage.Put(owner, record)
	if err != nil {
		return &rRpc.CreateEndpointResponse{}, gRpcStatus.Errorf(codes.Internal, "put ip allocate record to store error: %s", err.Error())
	}

	// Prepare the response.
	response := &rRpc.CreateEndpointResponse{
		IPSet: &rRpc.IPSet{
			IPv4: vpcIP.GetIPSet().IPv4.String(),
			IPv6: vpcIP.GetIPSet().IPv6.String(),
		},
		GatewayIP: &rRpc.IPSet{
			IPv4: podNetwork.Status.GatewayIP.IPv4,
			IPv6: podNetwork.Status.GatewayIP.IPv6,
		},
		Vid:        uint32(vpcIP.GetVid()),
		MacAddress: vpcIP.GetMacAddress(),
		CIDR: &rRpc.IPSet{
			IPv4: podNetwork.Spec.CIDR,
		},
		NetworkCardMacAddr: vpcIP.GetNetworkCardMacAddr(),
	}

	return response, nil
}

// DeleteEndpoint handles requests to delete an existing endpoint.
func (d *Daemon) DeleteEndpoint(ctx context.Context, request *rRpc.DeleteEndpointRequest) (*rRpc.DeleteEndpointResponse, error) {

	owner := fmt.Sprintf("%s/%s", request.GetK8SPodNamespace(), request.GetK8SPodName())
	// Get the Pod record from storage.
	record, err := d.recordStorage.Get(owner)
	if err != nil {
		if errors.Is(err, bolt.KeyNotFoundErr{}) {
			return &rRpc.DeleteEndpointResponse{}, nil
		}
		return &rRpc.DeleteEndpointResponse{}, gRpcStatus.Errorf(codes.Internal, "load record failed, key: %s, error is %s.", owner, err)
	}

	// If the last application fails, the pod name will not change, but the sandbox id will.
	if record.SandBoxId != request.GetK8SPodInfraContainerId() {
		return &rRpc.DeleteEndpointResponse{}, nil
	}

	// Release the IP associated with the Pod.
	releaseCtx := &types.PodReleaseContext{
		Context:    ctx,
		Name:       request.GetK8SPodName(),
		Namespace:  request.GetK8SPodNamespace(),
		SandBoxId:  request.GetK8SPodInfraContainerId(),
		ResourceId: record.ResourceId,
		Pool:       record.Pool,
		SubnetId:   record.SubnetId,
	}

	err = d.vpcResourceManager.ReleaseIP(releaseCtx)
	if err != nil {
		return &rRpc.DeleteEndpointResponse{}, gRpcStatus.Error(codes.Internal, err.Error())
	}

	// Delete the Pod record from storage.
	_, err = d.recordStorage.Delete(owner)
	if err != nil {
		return &rRpc.DeleteEndpointResponse{}, gRpcStatus.Errorf(codes.Internal, "delete record failed, key: %s, error is %s.", owner, err)
	}

	return &rRpc.DeleteEndpointResponse{
		TrunkMode: record.Trunk,
	}, nil
}

func initBoltEngine() (*bolt.BoltEngine, error) {
	// Check if the instance ID file exists.
	if _, err := os.Stat(types.InstanceIdFilePath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read instance id file error: %w", err)
	} else if os.IsNotExist(err) {
		// Remove old BoltDB file if the instance ID file does not exist.
		err := os.Remove(types.BoltDBPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove old db file error: %w", err)
		}
	}

	engine, err := bolt.NewEngine(types.BoltDBPath)
	if err != nil {
		return nil, fmt.Errorf("create bolt engine error: %w", err)
	}
	return engine, nil
}

func (d *Daemon) startHealthZAndPProfServer(ctx context.Context) {
	r := mux.NewRouter()
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})

	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(int(d.option.HealthzBindAddress)),
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Errorf("HealthZ server panic: %v", err)
			}
		}()

		err := server.ListenAndServe()
		if err != nil {
			log.Errorf("HealthZ server exit.")
		}
	}()

	log.Infof("HealthZ server started.")
	<-ctx.Done()
	server.Close()
	log.Infof("HealthZ server closed.")
}

// RestoreEndpoint restores Pod records from storage.
func (d *Daemon) RestoreEndpoint() ([]*types.PodRecord, error) {
	var podRecords []*types.PodRecord
	for _, record := range d.recordStorage.List() {

		// Check if the Pod still exists in the Kubernetes cluster.
		pod, err := d.k8sManager.GetPod(context.TODO(), record.Value.Namespace, record.Value.Name)
		if err != nil {
			if !k8sErr.IsNotFound(err) {
				return nil, err
			}
			// Delete the record if the Pod is not found.
			_, err = d.recordStorage.Delete(record.Key)
			if err != nil {
				return nil, err
			}
			log.Infof("Delete record %s from store, cause pod not found.", record.Key)
		} else {
			if pod.Status.PodIP == "" || len(pod.Status.PodIPs) == 0 {
				// Delete the record if the Pod ip not found.
				_, err = d.recordStorage.Delete(record.Key)
				if err != nil {
					return nil, err
				}
				continue
			}

			podRecord := &record.Value
			podRecord.Owner = record.Key
			podRecords = append(podRecords, podRecord)
			log.Infof("Record %s from store", record.Key)
		}
	}

	return podRecords, nil
}

func (d *Daemon) ListVpcIPs(ctx context.Context, request *rRpc.ListVpcIPsRequest) (*rRpc.ListVpcIPsResponse, error) {
	vpcIps := []*rRpc.VPCIP{}
	for _, subnetIps := range d.vpcResourceManager.ipStorageKeeper {
		for _, ip := range subnetIps.List() {
			IPSet := ip.Value.GetIPSet()
			ipPool := ip.Value.GetPool()
			ipSubId := ip.Value.GetSubnetId()
			if len(request.SubnetId) > 0 && request.SubnetId != ipSubId {
				continue
			}
			if len(request.Pool) > 0 && request.Pool != ipPool {
				continue
			}
			vpcIp := &rRpc.VPCIP{
				IPSet: &rRpc.IPSet{
					IPv4: IPSet.IPv4.String(),
					IPv6: IPSet.IPv6.String(),
				},
				PortId:            ip.Value.GetResourceId(),
				MACAddress:        ip.Value.GetMacAddress(),
				Vid:               int32(ip.Value.GetVid()),
				TrunkId:           ip.Value.GetTrunkId(),
				NetworkCardPortId: ip.Value.GetNetworkCardId(),
				SubnetId:          ipSubId,
				Pool:              ipPool,
			}
			vpcIps = append(vpcIps, vpcIp)
		}
	}
	return &rRpc.ListVpcIPsResponse{
		VPCIPs: vpcIps,
	}, nil
}

func (d *Daemon) ListNetworkCards(ctx context.Context, request *rRpc.ListNetworkCardsRequest) (*rRpc.ListNetworkCardsResponse, error) {
	netCards := []*rRpc.CliNetworkCard{}
	cards := d.networkStorage.List()

	for _, card := range cards {
		IPSet := card.Value.GetIPSet()
		netCard := &rRpc.CliNetworkCard{
			NetworkCardPortId: card.Value.GetResourceId(),
			MACAddress:        card.Value.GetMacAddress(),
			IPSet: &rRpc.IPSet{
				IPv4: IPSet.IPv4.String(),
				IPv6: IPSet.IPv6.String(),
			},
			SecurityGroups: card.Value.GetSecurityGroups(),
			SubnetId:       card.Value.GetSubnetId(),
			NetworkId:      card.Value.GetNetworkId(),
			TrunkId:        card.Value.GetTrunkId(),
			IPLimit:        int32(card.Value.GetIPLimit()),
		}
		netCards = append(netCards, netCard)
	}
	return &rRpc.ListNetworkCardsResponse{
		CliNetworkCards: netCards,
	}, nil
}

func (d *Daemon) getPortIdMapIPs() map[string]*types.IPs {
	portMapIp := make(map[string]*types.IPs)
	for _, subnetIps := range d.vpcResourceManager.ipStorageKeeper {
		for _, ip := range subnetIps.List() {
			portId := ip.Value.GetResourceId()
			IPSet := ip.Value.GetIPSet()
			portMapIp[portId] = &types.IPs{
				IPSet: &rRpc.IPSet{
					IPv4: IPSet.IPv4.String(),
					IPv6: IPSet.IPv6.String(),
				},
				MACAddress:        ip.Value.GetMacAddress(),
				Vid:               int32(ip.Value.GetVid()),
				TrunkId:           ip.Value.GetTrunkId(),
				NetworkCardPortId: ip.Value.GetNetworkCardId(),
			}
		}
	}
	return portMapIp
}

func (d *Daemon) ListPodRecords(ctx context.Context, request *rRpc.ListPodRecordsRequest) (*rRpc.ListPodRecordsResponse, error) {
	podRecords := []*rRpc.PodRecord{}
	records := d.recordStorage.List()
	portMapIps := d.getPortIdMapIPs()
	for _, record := range records {
		if len(request.SubnetId) > 0 && request.SubnetId != record.Value.SubnetId {
			continue
		}
		if len(request.Pool) > 0 && request.Pool != record.Value.Pool {
			continue
		}
		if len(request.Namespace) > 0 && request.Namespace != record.Value.Namespace {
			continue
		}
		portId := record.Value.ResourceId
		portIps := portMapIps[portId]
		podRecord := &rRpc.PodRecord{
			Pool:              record.Value.Pool,
			PortId:            portId,
			SubnetId:          record.Value.SubnetId,
			Name:              record.Value.Name,
			Namespace:         record.Value.Namespace,
			Trunk:             record.Value.Trunk,
			IPSet:             portIps.IPSet,
			MACAddress:        portIps.MACAddress,
			Vid:               portIps.Vid,
			TrunkId:           portIps.TrunkId,
			NetworkCardPortId: portIps.NetworkCardPortId,
		}
		podRecords = append(podRecords, podRecord)
	}
	return &rRpc.ListPodRecordsResponse{
		PodRecords: podRecords,
	}, nil
}
