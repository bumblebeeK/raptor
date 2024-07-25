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
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/datapath"
	"github.com/easystack/raptor/pkg/datapath/device"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type MultiIP struct {
	base.Log
}

func (d *MultiIP) Name() string {
	return "multiIP"
}

// NewMultiIPDriver creates multi_ip driver.
func NewMultiIPDriver(log base.Log) datapath.Driver {
	return &MultiIP{log}
}

func (d *MultiIP) SetupNetwork(cfg *types.SetupConfig) (err error) {

	veth := &device.VethConf{
		HostIfName: cfg.HostVethName,
		TmpIfName:  cfg.ContVethName,
		ContIfName: cfg.ContIfaceName,
	}

	netNs, err := ns.GetNS(cfg.NetNSPath)
	if err != nil {
		return fmt.Errorf("get netNs [%s] failed: %w", cfg.NetNSPath, err)
	}
	defer netNs.Close()

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

	tableId := utils.GetRouteTableID(cfg.MasterIface)

	vethConf := &device.Conf{}
	if cfg.IPSet.IPv4 != nil {
		vethConf.Routes = append(vethConf.Routes,
			&netlink.Route{
				LinkIndex: hostVeth.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       cfg.IPSet.IPv4,
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

func (d *MultiIP) TeardownNetwork(cfg *types.TeardownConfig) (err error) {
	return nil
}
