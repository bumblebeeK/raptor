// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package datapath

import (
	"crypto/sha256"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"net"

	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/easystack/raptor/rpc"
	"golang.org/x/sys/unix"
)

const (
	hostInterfacePrefix      = "rpt"
	temporaryInterfacePrefix = "tmp"
	vlanInterfacePrefix      = "vlan"
)

type Driver interface {
	Name() string
	SetupNetwork(cfg *types.SetupConfig) (err error)
	TeardownNetwork(cfg *types.TeardownConfig) (err error)
}

func ParseSetupConfig(info *rpc.CreateEndpointResponse, args *types.CNIAddArgs) (error, *types.SetupConfig) {

	gateway := types.IPNetSet{}
	ipSet := types.IPNetSet{}

	if info.GetIPSet().GetIPv4() != "" && info.GetGatewayIP().GetIPv4() != "" {
		gateway.IPv4 = &net.IPNet{
			IP:   net.ParseIP(info.GetGatewayIP().GetIPv4()),
			Mask: net.CIDRMask(32, 32),
		}
		ipSet.IPv4 = &net.IPNet{
			IP:   net.ParseIP(info.GetIPSet().GetIPv4()),
			Mask: net.CIDRMask(32, 32),
		}
	}

	if info.GetIPSet().GetIPv6() != "" && info.GetGatewayIP().GetIPv6() != "" {
		gateway.IPv6 = &net.IPNet{
			IP:   net.ParseIP(info.GetGatewayIP().GetIPv6()),
			Mask: net.CIDRMask(128, 128),
		}
		ipSet.IPv6 = &net.IPNet{
			IP:   net.ParseIP(info.GetIPSet().GetIPv6()),
			Mask: net.CIDRMask(128, 128),
		}
	}

	macAddr, err := net.ParseMAC(info.GetMacAddress())
	if err != nil {
		return fmt.Errorf("Invalid mac address: %s", info.GetMacAddress()), nil
	}

	masterMacAddr, err := net.ParseMAC(info.GetNetworkCardMacAddr())
	if err != nil {
		return fmt.Errorf("Invalid network card mac address: %s", info.GetNetworkCardMacAddr()), nil
	}

	err, masterIfaceLink := utils.GetNetlinkByMac(masterMacAddr)

	if err != nil {
		return fmt.Errorf("Failed to get master link by mac %v", info.GetNetworkCardMacAddr()), nil
	}

	var setupCfg = &types.SetupConfig{
		Gateway:       gateway,
		Vid:           int(info.GetVid()),
		MTU:           int(info.GetMTU()),
		NetNSPath:     args.NetNS,
		MacAddr:       macAddr,
		MasterMacAddr: masterMacAddr,
		IPSet:         ipSet,

		MasterIface: masterIfaceLink,

		HostVethName:  GenerateHostVethName(args.K8sArgs.K8sInfraContainerID),
		VlanIfaceName: GenerateVlanIfName(args.K8sArgs.K8sInfraContainerID),
		ContVethName:  GenerateTempIfName(args.K8sArgs.K8sInfraContainerID),
		ContIfaceName: types.DefaultContIfaceName,
	}

	if setupCfg.Vid == 0 {
		setupCfg.DP = types.MultiIP
	} else {
		// TODO support vlan
		setupCfg.DP = types.VlanChaining
	}

	return nil, setupCfg
}

func ParseTeardownConfig(info *rpc.DeleteEndpointResponse, args *skel.CmdArgs) *types.TeardownConfig {
	config := &types.TeardownConfig{}

	if info.TrunkMode {
		config.DP = types.VlanChaining
	}
	return config
}

// GenerateHostVethName returns the host interface name for the given endpointID.
func GenerateHostVethName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(hostInterfacePrefix) - 1)
	return hostInterfacePrefix + truncateString(sum, truncateLength)
}

// GenerateVlanIfName returns the host interface name for the given endpointID.
func GenerateVlanIfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(vlanInterfacePrefix) - 1)
	return vlanInterfacePrefix + truncateString(sum, truncateLength)
}

// GenerateTempIfName returns the temporary interface name for the given
// endpointID.
func GenerateTempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}
