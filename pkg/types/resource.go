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

	"github.com/easystack/raptor/rpc"
)

// NetworkCard defines an interface for network cards, providing a series of methods to access network card properties.
type NetworkCard interface {
	// GetResourceId returns the resource ID.
	GetResourceId() string
	// GetNetworkId returns the network ID.
	GetNetworkId() string
	// GetSubnetId returns the tag of the network card.
	GetSubnetId() string
	// GetTrunkId returns the trunk ID.
	GetTrunkId() string
	// GetMacAddress returns the MAC address of the network card.
	GetMacAddress() string

	GetIPSet() IPSet

	GetSecurityGroups() []string

	GetIPLimit() int
}

// NetworkCardImpl is a concrete implementation of the NetworkCard interface, containing various properties of a network card.
type NetworkCardImpl struct {
	IPSet          IPSet    // Set of IP addresses
	MacAddress     string   // MAC address
	TrunkId        string   // Trunk ID
	ResourceId     string   // Resource ID
	SecurityGroups []string // Security groups
	NetworkId      string   // Network ID
	SubnetId       string   // Subnet ID
	IPLimit        int      // IP limit
}

// ResourceId returns the resource ID of the network card.
func (n NetworkCardImpl) GetResourceId() string {
	return n.ResourceId
}

func (n NetworkCardImpl) GetIPLimit() int {
	return n.IPLimit
}

func (n NetworkCardImpl) GetSecurityGroups() []string {
	return n.SecurityGroups
}

// GetNetworkCardId returns the network card ID.
func (n NetworkCardImpl) GetNetworkId() string {
	return n.NetworkId
}

// SubNetId returns the subnet ID of the network card.
func (n NetworkCardImpl) GetSubnetId() string {
	return n.SubnetId
}

// TrunkId returns the trunk ID of the network card.
func (n NetworkCardImpl) GetTrunkId() string {
	return n.TrunkId
}

// MacAddress returns the MAC address of the network card.
func (n NetworkCardImpl) GetMacAddress() string {
	return n.MacAddress
}

func (n NetworkCardImpl) GetIPSet() IPSet {
	return n.IPSet
}

// TranslateNetworkCard converts an rpc.NetworkCard object to a NetworkCard interface.
func TranslateNetworkCard(card *rpc.NetworkCard) NetworkCard {

	return NetworkCardImpl{
		IPSet: IPSet{
			IPv4: net.ParseIP(card.GetIPSet().GetIPv4()),
			IPv6: net.ParseIP(card.GetIPSet().GetIPv6()),
		},
		MacAddress:     card.GetMAC(),
		TrunkId:        card.GetTrunkID(),
		ResourceId:     card.GetID(),
		SecurityGroups: card.SecurityGroups,
		NetworkId:      card.GetNetworkId(),
		SubnetId:       card.GetSubnetId(),
		IPLimit:        DefaultNetworkCardLimit,
	}
}

// VPCIP defines an interface for VPC IP addresses, providing a series of methods to access IP properties.
type VPCIP interface {
	// ResourceId returns the resource ID.
	GetResourceId() string
	// NetworkId returns the network ID.
	GetNetworkId() string
	// SubnetId returns the subnet ID.
	GetSubnetId() string
	// Vid returns the VLAN ID.
	GetVid() int
	// MacAddress returns the MAC address.
	GetMacAddress() string
	// NetworkCardId returns the network card ID.
	GetNetworkCardId() string
	// Pool returns the IP pool.
	GetPool() string
	// IPSet returns the set of IP addresses.
	GetIPSet() IPSet
	// TrunkId returns the trunk ID of the VPC IP.
	GetTrunkId() string

	GetNetworkCardMacAddr() string
}

// VPCIPImpl is a concrete implementation of the VPCIP interface, containing various properties of a VPC IP.
type VPCIPImpl struct {
	ResourceId            string `json:"resource-id"`      // Resource ID
	IPSet                 IPSet  `json:"ip-set"`           // Set of IP addresses
	MacAddress            string `json:"mac-address"`      // MAC address
	Vid                   int    `json:"vid"`              // VLAN ID
	Pool                  string `json:"pool"`             // IP Pool
	TrunkId               string `json:"trunk-id"`         // Trunk ID
	NetworkCardId         string `json:"network-card-id"`  // NetworkCard
	NetworkCardMacAddress string `json:"network-card-mac"` // NetworkCard
	NetworkId             string `json:"network-id"`
	SubnetId              string `json:"subnet-id"`
}

func (v VPCIPImpl) GetSubnetId() string {
	return v.SubnetId
}

// Vid returns the VLAN ID of the VPC IP.
func (v VPCIPImpl) GetVid() int {
	return v.Vid
}

// MacAddress returns the MAC address of the VPC IP.
func (v VPCIPImpl) GetMacAddress() string {
	return v.MacAddress
}

// NetworkCardId returns the network card ID of the VPC IP.
func (v VPCIPImpl) GetNetworkCardId() string {
	return v.NetworkCardId
}

// Pool returns the IP pool of the VPC IP.
func (v VPCIPImpl) GetPool() string {
	return v.Pool
}

// IPSet returns the set of IP addresses of the VPC IP.
func (v VPCIPImpl) GetIPSet() IPSet {
	return v.IPSet
}

// TrunkId returns the trunk ID of the VPC IP.
func (v VPCIPImpl) GetTrunkId() string {
	return v.TrunkId
}

// ResourceId returns the resource ID of the VPC IP.
func (v VPCIPImpl) GetResourceId() string {
	return v.ResourceId
}

// NetworkId returns the network ID of the VPC IP.
func (v VPCIPImpl) GetNetworkId() string {
	return v.NetworkId
}

func (v VPCIPImpl) GetNetworkCardMacAddr() string {
	return v.NetworkCardMacAddress
}

// TranslateVPCIP converts an rpc.PodIP object to a VPCIP interface.
func TranslateVPCIP(vpcIP *rpc.VPCIP, card NetworkCard) VPCIP {
	return &VPCIPImpl{
		ResourceId: vpcIP.GetPortId(),
		IPSet: IPSet{
			IPv4: net.ParseIP(vpcIP.GetIPSet().GetIPv4()),
			IPv6: net.ParseIP(vpcIP.GetIPSet().GetIPv6()),
		},
		MacAddress:            vpcIP.GetMACAddress(),
		Vid:                   int(vpcIP.GetVid()),
		Pool:                  vpcIP.GetPool(),
		NetworkCardId:         card.GetResourceId(),
		NetworkCardMacAddress: card.GetMacAddress(),
		TrunkId:               card.GetTrunkId(),
		SubnetId:              vpcIP.GetSubnetId(),
	}
}

type IPPool struct {
	PoolName    string `json:"poolName"`
	NetworkID   string `json:"networkID"`
	SubnetID    string `json:"subnetID"`
	TrunkMode   bool   `json:"trunkMode"`
	GatewayIPv4 string `json:"gatewayIPv4"`
	GatewayIPv6 string `json:"gatewayIPv6"`
	GatewayIP   string `json:"gatewayIP"`
	SubnetCidr  string `json:"subnetCidr"`
}
