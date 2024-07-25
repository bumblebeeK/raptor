package device

import (
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// VethConf is interface config for veth pair.
type VethConf struct {
	HostIfName string
	TmpIfName  string
	ContIfName string
	MTU        int
}

// Setup veth pair interface for netns.
func (vethConf *VethConf) Setup(netNS ns.NetNS) error {
	peer, err := netlink.LinkByName(vethConf.TmpIfName)
	if err == nil {
		err = netlink.LinkDel(peer)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return err
			}
		}
	}

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			MTU:       vethConf.MTU,
			Name:      vethConf.TmpIfName,
			Namespace: netlink.NsFd(int(netNS.Fd())),
		},
		PeerName: vethConf.HostIfName,
	}
	err = netlink.LinkAdd(link)
	if err != nil {
		return err
	}

	return nil
}
