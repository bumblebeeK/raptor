package device

import (
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/easystack/raptor/pkg/base"
	itypes "github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/vishvananda/netlink"
	"net"
)

var log = base.NewLogWithField("subsys", "vlan")

// VlanConfig is interface config of vlan slave.
type VlanConfig struct {
	MasterName   string
	IfName       string
	Vid          int
	MTU          int
	HardwareAddr net.HardwareAddr
	Address      []*netlink.Addr
	Gateway      itypes.IPNetSet
	MasterLink   netlink.Link
}

// Setup vlan slave for netns.
func (vlanConfig *VlanConfig) Setup(netNS ns.NetNS) error {
	var err error
	// vlanName := generateVlanDeviceName(master.Attrs().Name, vlanConfig.GetVid)
	err, vlan := utils.GetNetlinkByVlan(vlanConfig.Vid, vlanConfig.MasterLink)
	if err == nil {
		err1 := netlink.LinkDel(vlan)
		if err1 != nil {
			log.Errorf("delete link failed, error is %s", err1.Error())
			return err1
		}
	} else {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			log.Errorf("link vlan iface failed, error is %s", err.Error())
			return err
		}

	}

	vlan = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          vlanConfig.MasterLink.Attrs().MTU,
			Name:         vlanConfig.IfName,
			ParentIndex:  vlanConfig.MasterLink.Attrs().Index,
			HardwareAddr: vlanConfig.HardwareAddr,
		},
		VlanId: vlanConfig.Vid,
	}
	vlan.Attrs().HardwareAddr = vlanConfig.HardwareAddr

	err = netlink.LinkAdd(vlan)
	if err != nil {
		log.Errorf("add vlan device failed, error is %s", err.Error())
		return err
	}

	vlanIface, err := netlink.LinkByName(vlanConfig.IfName)
	if err != nil {
		log.Errorf("failed to get vlan iface, error is %s", err.Error())
		return err
	}

	for _, address := range vlanConfig.Address {
		err = netlink.AddrAdd(vlanIface, address)
		if err != nil {
			log.Errorf("failed to add addr for vlan iface, error is %s", err.Error())
			return err
		}
	}

	err = netlink.LinkSetUp(vlanIface)
	if err != nil {
		log.Errorf("failed to set vlan link up, error is %s", err.Error())
		return err
	}

	return nil
}
