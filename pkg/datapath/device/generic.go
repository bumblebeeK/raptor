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
//

package device

import (
	"fmt"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"net"

	"github.com/vishvananda/netlink"
)

// Conf indicates network devices configures.
type Conf struct {
	IfName string
	MTU    int

	Addresses []*netlink.Addr
	Routes    []*netlink.Route
	Rules     []*netlink.Rule
	Neighs    []*netlink.Neigh
	SysCtl    [][]string
}

func SetupLink(link netlink.Link, conf *Conf) error {
	var err error
	if conf.IfName != "" && link.Attrs().Name != conf.IfName {
		err = netlink.LinkSetName(link, conf.IfName)
		if err != nil {
			return fmt.Errorf("link set name failed: %s", err.Error())
		}
		link, err = netlink.LinkByName(conf.IfName)
		if err != nil {
			return fmt.Errorf("could not find interface %d inside netns after name changed", link.Attrs().Index)
		}
	}

	if link.Attrs().OperState != netlink.OperUp {
		err = netlink.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to bring link %s up: %w", link.Attrs().Name, err)
		}
	}

	if conf.MTU > 0 && link.Attrs().MTU != conf.MTU {
		err = netlink.LinkSetMTU(link, conf.MTU)
		if err != nil {
			return fmt.Errorf("link %d set mtu failed: %s", link.Attrs().Index, err.Error())
		}
	}

	for _, addr := range conf.Addresses {
		err = netlink.AddrReplace(link, addr)
		if err != nil {
			return fmt.Errorf("add address %s to link %s failed: %w", addr.String(), link.Attrs().Name, err)
		}
	}

	for _, neigh := range conf.Neighs {
		err := netlink.NeighAdd(neigh)
		if err != nil {
			return fmt.Errorf("add neigh failed: %w", err)
		}
	}

	for _, route := range conf.Routes {
		err := netlink.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("add route failed: %w", err)
		}
	}

	for _, rule := range conf.Rules {
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("add rule failed: %w", err)
		}

	}
	return nil
}

// EnsureNetConfSet calls sysctl to ensure system network config.
func EnsureNetConfSet(link netlink.Link, item, conf string) error {
	_, err := sysctl.Sysctl(fmt.Sprintf(item, link.Attrs().Name), conf)
	if err != nil {
		return fmt.Errorf("ensure net config %s to %s failed: %s", item, conf, err.Error())
	}
	return nil
}

// EnsureIPRule add specified rule if it not exists.
func EnsureIPRule(expected *netlink.Rule) error {
	ruleList, err := FindIPRule(expected)
	if err != nil {
		return err
	}
	found := false
	for i, rule := range ruleList {
		del := false
		if rule.Table != expected.Table {
			del = true
		}
		if rule.Priority != expected.Priority {
			del = true
		}
		if rule.IifName != expected.IifName {
			del = true
		}
		if del {
			err = netlink.RuleDel(&ruleList[i])
			if err != nil {
				return err
			}
		} else {
			found = true
		}
	}
	if found {
		return nil
	}
	return netlink.RuleAdd(expected)
}

// FindIPRule lookup expected rules.
func FindIPRule(rule *netlink.Rule) ([]netlink.Rule, error) {
	var filterMask uint64
	family := netlink.FAMILY_V4

	if rule.Src == nil && rule.Dst == nil && rule.OifName == "" {
		return nil, fmt.Errorf("both src and dst is nil")
	}

	if rule.Src != nil {
		filterMask |= netlink.RT_FILTER_SRC
		family = NetlinkFamily(rule.Src.IP)
	}
	if rule.Dst != nil {
		filterMask |= netlink.RT_FILTER_DST
		family = NetlinkFamily(rule.Dst.IP)
	}
	if rule.OifName != "" {
		filterMask |= netlink.RT_FILTER_OIF
		family = netlink.FAMILY_V4
	}

	if rule.Priority >= 0 {
		filterMask |= netlink.RT_FILTER_PRIORITY
	}
	return netlink.RuleListFiltered(family, rule, filterMask)
}

// NetlinkFamily return family of ip.
func NetlinkFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}
