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

package types

import (
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/easystack/raptor/pkg/storage"
	"github.com/easystack/raptor/rpc"
	"github.com/vishvananda/netlink"
)

const (
	DefaultSocketPath    = "/var/run/cni/raptor.socket"
	DefaultCNILockPath   = "/var/run/cni/raptor.lock"
	DefaultCNITimeout    = 10 * time.Second
	StaticPodAnnotation  = "raptor.io/static-ip-needed"
	PodNetworkAnnotation = "raptor.io/pod-network"
	PodSandboxAnnotation = "raptor.io/pod-sandbox"

	BoltDBPath         = "/var/run/cni/raptor.db"
	InstanceIdFilePath = "/var/run/cni/instanceId"

	TrunkNetworkAnnotation  = "raptor.io/trunk-network-card"
	LocalPodIndexerKey      = "local-pod"
	ToContainerPriority     = 20
	FromContainerPriority   = 100
	TrunkNetworkCard        = "TrunkNetworkCard"
	DefaultNetworkCardLimit = 100

	DefaultContIfaceName = "eth0"
)

var (
	_, DefaultRoute, _     = net.ParseCIDR("0.0.0.0/0")
	_, DefaultRouteIPv6, _ = net.ParseCIDR("::/0")
	LinkIP                 = net.IPv4(169, 254, 1, 1)
	LinkIPv6               = net.ParseIP("fe80::1")
	LinkIPNet              = &net.IPNet{
		IP:   LinkIP,
		Mask: net.CIDRMask(32, 32),
	}
	LinkIPNetv6 = &net.IPNet{
		IP:   LinkIPv6,
		Mask: net.CIDRMask(128, 128),
	}
)

type NetConf struct {
	cniTypes.NetConf
	Master string `json:"master"`
	Mode   string `json:"mode"`
	MTU    int    `json:"mtu"`
}

type IpStorageCreator func(subnetId string, pool IPPool) (storage.Storage[VPCIP], error)

type IpStorageFinalizer func(name string) error

type K8sArgs struct {
	K8sPodName          string
	K8sPodNameSpace     string
	K8sInfraContainerID string
	K8sServiceCidr      string
}

type TrunkInfo struct {
	TrunkId       string `json:"trunk_id"`
	TrunkParentId string `json:"trunk_parent_id"`
}

type CNIAddArgs struct {
	*NetConf
	*K8sArgs
	RawArgs *skel.CmdArgs
	NetNS   string
}

type DataPath int

const (
	MultiIP      DataPath = iota
	VlanChaining          // Chaining cilium
	Vlan
)

type IPNetSet struct {
	IPv4 *net.IPNet
	IPv6 *net.IPNet
}

// IPSet is the type hole both ipv4 and ipv6 net.IP
type IPSet struct {
	IPv4 net.IP `json:"ipv4,omitempty"`
	IPv6 net.IP `json:"ipv6,omitempty"`
}

type SetupConfig struct {
	DP DataPath

	HostVethName string
	ContVethName string

	ContIfaceName string
	VlanIfaceName string

	IPSet   IPNetSet
	Gateway IPNetSet

	MacAddr       net.HardwareAddr
	MasterMacAddr net.HardwareAddr

	MasterIface netlink.Link

	Vid       int
	MTU       int
	NetNSPath string
}

type TeardownConfig struct {
	DP DataPath

	ContainerID string

	ContainerIPNet *IPNetSet
}

type IPs struct {
	IPSet             *rpc.IPSet
	Vid               int32
	MACAddress        string
	TrunkId           string
	NetworkCardPortId string
}
