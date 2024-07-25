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

package driver

import (
	"fmt"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/datapath"
	"github.com/easystack/raptor/pkg/datapath/device"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/pkg/utils"
	"syscall"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type ChainingVlan struct {
	base.Log
}

// NewVlanDriver creates vlan driver.
func NewVlanDriver(log base.Log) datapath.Driver {
	return &ChainingVlan{log}
}

// Name will return the name of Vlan driver.
func (d *ChainingVlan) Name() string {
	return "chainingVlan"
}

// GetDefaultRoute get the default route of the corresponding family.
func GetDefaultRoute(family int) (*netlink.Route, error) {
	if family != netlink.FAMILY_ALL && family != netlink.FAMILY_V4 && family != netlink.FAMILY_V6 {
		return nil, fmt.Errorf("family must be FAMILY_V6 or FAMILY_V4")
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{}, netlink.RT_FILTER_DST)
	if err != nil || len(routes) == 0 {
		return nil, fmt.Errorf("default route not found")
	}

	return &routes[0], nil
}

// SetupNetwork sets vlan data path up.
func (d *ChainingVlan) SetupNetwork(cfg *types.SetupConfig) (err error) {

	if cfg.MasterIface.Attrs().OperState != netlink.OperUp {
		err = netlink.LinkSetUp(cfg.MasterIface)
		if err != nil {
			return fmt.Errorf("failed to bring link %s up: %w", cfg.MasterIface.Attrs().Name, err)
		}
	}

	netNs, err := ns.GetNS(cfg.NetNSPath)
	if err != nil {
		return fmt.Errorf("get netNs [%s] failed: %w", cfg.NetNSPath, err)
	}
	defer netNs.Close()

	vlanCfg := &device.VlanConfig{
		IfName:       cfg.VlanIfaceName,
		MasterName:   cfg.MasterIface.Attrs().Name,
		Vid:          cfg.Vid,
		MTU:          cfg.MasterIface.Attrs().MTU,
		HardwareAddr: cfg.MacAddr,
		Address:      utils.NewIPNetToMaxMask(&cfg.IPSet),
		MasterLink:   cfg.MasterIface,

		Gateway: cfg.Gateway,
	}

	err = vlanCfg.Setup(netNs)
	if err != nil {
		return fmt.Errorf("setup vlan device error, %s", err.Error())
	}

	vlanIf, err := netlink.LinkByName(cfg.VlanIfaceName)
	if err != nil {
		return fmt.Errorf("failed to get vlan interface, error is %s", err.Error())
	}

	veth := &device.VethConf{
		HostIfName: cfg.HostVethName,
		TmpIfName:  cfg.ContVethName,
		ContIfName: cfg.ContIfaceName,
	}

	err = veth.Setup(netNs)
	if err != nil {
		return fmt.Errorf("setup veth pair error, %s", err.Error())
	}

	hostVeth, err := netlink.LinkByName(cfg.HostVethName)
	if err != nil {
		return fmt.Errorf("get host veth error, %s", err.Error())
	}
	err = netNs.Do(func(_ ns.NetNS) error {

		contEth0, inErr := netlink.LinkByName(cfg.ContVethName)
		if inErr != nil {
			return inErr
		}

		vethConf, inErr := generateVethConf(cfg, contEth0, hostVeth)
		if inErr != nil {
			return inErr
		}

		return device.SetupLink(contEth0, vethConf)

	})
	if err != nil {
		return fmt.Errorf("setup network error, %s", err.Error())
	}

	tableId := utils.GetRouteTableID(hostVeth)

	filtered, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: tableId}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}

	for _, route := range filtered {
		netlink.RouteDel(&route)
	}

	vethConf := &device.Conf{}
	if cfg.IPSet.IPv4 != nil {
		gw := cfg.Gateway.IPv4
		vethConf.Routes = append(vethConf.Routes,
			&netlink.Route{
				LinkIndex: hostVeth.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       cfg.IPSet.IPv4,
			},
			&netlink.Route{
				Dst:       gw,
				LinkIndex: vlanIf.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Protocol:  syscall.RTPROT_KERNEL,
				Table:     tableId,
			},
			&netlink.Route{
				Protocol:  syscall.RTPROT_KERNEL,
				Table:     tableId,
				LinkIndex: vlanIf.Attrs().Index,
				Gw:        gw.IP,
				Dst:       nil,
			})
		toCont := netlink.NewRule()
		toCont.Dst = cfg.IPSet.IPv4
		toCont.Table = unix.RT_TABLE_MAIN
		toCont.Priority = types.ToContainerPriority

		fromCont := netlink.NewRule()
		fromCont.Src = cfg.IPSet.IPv4
		fromCont.IifName = hostVeth.Attrs().Name
		fromCont.Table = tableId
		fromCont.Priority = types.FromContainerPriority
		vethConf.Rules = append(vethConf.Rules, toCont, fromCont)
	}

	err = device.SetupLink(hostVeth, vethConf)
	if err != nil {
		return fmt.Errorf("setup veth link %s in host ns failed, %s", hostVeth.Attrs().Name, err.Error())
	}

	d.Infof("Setup veth in host ns success")

	return nil
}

func generateVethConf(cfg *types.SetupConfig, podLink, hostLink netlink.Link) (*device.Conf, error) {
	var addrs []*netlink.Addr
	var routes []*netlink.Route
	var neigh []*netlink.Neigh

	if cfg.IPSet.IPv4 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: cfg.IPSet.IPv4})
		routes = append(routes, &netlink.Route{
			Dst:       types.DefaultRoute,
			Gw:        cfg.Gateway.IPv4.IP,
			Flags:     int(netlink.FLAG_ONLINK),
			LinkIndex: podLink.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
		})
		neigh = append(neigh, &netlink.Neigh{
			LinkIndex:    podLink.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           cfg.Gateway.IPv4.IP,
			HardwareAddr: hostLink.Attrs().HardwareAddr,
		})
	}

	if cfg.IPSet.IPv6 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: cfg.IPSet.IPv6})
		routes = append(routes, &netlink.Route{
			Dst:       types.DefaultRoute,
			Gw:        cfg.Gateway.IPv6.IP,
			Flags:     int(netlink.FLAG_ONLINK),
			LinkIndex: podLink.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
		})

		neigh = append(neigh, &netlink.Neigh{
			LinkIndex:    podLink.Attrs().Index,
			State:        netlink.NUD_PERMANENT,
			IP:           cfg.Gateway.IPv6.IP,
			HardwareAddr: hostLink.Attrs().HardwareAddr,
		})
	}

	return &device.Conf{
		IfName:    cfg.ContIfaceName,
		Addresses: addrs,
		Routes:    routes,
		Neighs:    neigh,
	}, nil
}

func (d *ChainingVlan) TeardownNetwork(cfg *types.TeardownConfig) (err error) {

	vlanIfName := datapath.GenerateVlanIfName(cfg.ContainerID)

	vlanIf, err := netlink.LinkByName(vlanIfName)

	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return err
		}
	} else {
		err := netlink.LinkDel(vlanIf)
		if err != nil {
			return err
		}
	}

	return nil
}
