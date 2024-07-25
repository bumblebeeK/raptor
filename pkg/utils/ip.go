package utils

import (
	"fmt"
	"github.com/easystack/raptor/pkg/types"
	"github.com/vishvananda/netlink"
	"net"
	"os/exec"
	"syscall"
)

// DisableRpFilter tries to disable rpfilter on specified interface
func DisableRpFilter(ifName string) error {
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", ifName))
	return cmd.Run()
}

func AddSubnetRoute(dst *net.IPNet, linkIndex, tableID int, gw net.IP) error {
	subnetRoute := &netlink.Route{
		Dst:       dst,
		LinkIndex: linkIndex,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  syscall.RTPROT_KERNEL,
		Table:     tableID,
	}

	err := netlink.RouteAdd(subnetRoute)

	if err != nil && err != syscall.EEXIST {
		return err
	}

	defaultRoute := &netlink.Route{
		Protocol:  syscall.RTPROT_KERNEL,
		Table:     tableID,
		LinkIndex: linkIndex,
		Gw:        gw,
		Dst:       nil,
	}

	err = netlink.RouteAdd(defaultRoute)
	if err != nil && err != syscall.EEXIST {
		return err

	}

	return nil
}

func addSubnetRule(link netlink.Link, tableID int, networkCardAddress net.IP, subnetCidr *net.IPNet) error {

	rule := netlink.NewRule()
	rule.Src = subnetCidr
	rule.Table = tableID
	rule.Priority = 1000
	err := netlink.RuleAdd(rule)
	if err != nil && err != syscall.EEXIST {
		return err
	}
	//addr := &netlink.Addr{}
	//addr.IPNet = &net.IPNet{
	//	IP:   networkCardAddress,
	//	Mask: subnetCidr.Mask,
	//}
	//
	//err = netlink.AddrAdd(link, addr)
	//if err != nil && err != syscall.EEXIST {
	//	return err
	//}

	return nil
}

func TeardownPodNetwork(ip string) error {
	rule := netlink.NewRule()
	rule.Dst = &net.IPNet{
		IP:   net.ParseIP(ip),
		Mask: net.CIDRMask(32, 32),
	}
	return netlink.RuleDel(rule)
}

func NewIPNetWithMaxMask(ipNet *net.IPNet) *net.IPNet {
	if ipNet.IP.To4() == nil {
		return &net.IPNet{
			IP:   ipNet.IP,
			Mask: net.CIDRMask(128, 128),
		}
	}
	return &net.IPNet{
		IP:   ipNet.IP,
		Mask: net.CIDRMask(32, 32),
	}
}

func NewIPNetToMaxMask(ipNet *types.IPNetSet) []*netlink.Addr {
	var addrs []*netlink.Addr
	if ipNet.IPv4 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: NewIPNetWithMaxMask(ipNet.IPv4)})
	}
	if ipNet.IPv6 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: NewIPNetWithMaxMask(ipNet.IPv6)})
	}
	return addrs
}

func NewIPNet(ipNet *types.IPNetSet) *types.IPNetSet {
	ipNetSet := &types.IPNetSet{}
	if ipNet.IPv4 != nil {
		ipNetSet.IPv4 = NewIPNetWithMaxMask(ipNet.IPv4)
	}
	if ipNet.IPv6 != nil {
		ipNetSet.IPv6 = NewIPNetWithMaxMask(ipNet.IPv6)
	}
	return ipNetSet
}

func EnsureClsActQdsic(link netlink.Link) error {
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	for _, q := range qds {
		if q.Type() == "clsact" {
			return nil
		}
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.HANDLE_CLSACT & 0xffff0000,
		},
		QdiscType: "clsact",
	}
	if err = QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("replace clsact qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	return nil
}

func QdiscReplace(qdisc netlink.Qdisc) error {
	cmd := fmt.Sprintf("tc qdisc replace %s", qdisc.Attrs().String())
	log.Infof(cmd)
	err := netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

func NewIPNet1(ipNet *types.IPNetSet) []*netlink.Addr {
	var addrs []*netlink.Addr
	if ipNet.IPv4 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: ipNet.IPv4})
	}
	if ipNet.IPv6 != nil {
		addrs = append(addrs, &netlink.Addr{IPNet: ipNet.IPv6})
	}
	return addrs
}
