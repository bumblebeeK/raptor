package utils

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"os"
)

func GetLinkByMac(mac string) (netlink.Link, error) {
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range linkList {
		if link.Attrs().HardwareAddr.String() == mac {
			return link, nil
		}
	}

	return nil, os.ErrNotExist
}

func EnsureLinkName(link netlink.Link, name string) (bool, error) {
	if link.Attrs().Name == name {
		return false, nil
	}
	return true, LinkSetName(link, name)
}

func EnsureAddr(link netlink.Link, expect *netlink.Addr) (bool, error) {
	var changed bool

	addrList, err := netlink.AddrList(link, NetlinkFamily(expect.IP))
	if err != nil {
		return false, fmt.Errorf("error list address from if %s, %w", link.Attrs().Name, err)
	}

	found := false
	for _, addr := range addrList {
		if !addr.IP.IsGlobalUnicast() {
			continue
		}

		if (addr.IPNet.String() == expect.IPNet.String()) && (addr.Scope == expect.Scope) {
			found = true
			continue
		}

		err := AddrDel(link, &addr)
		if err != nil {
			return false, err
		}
		changed = true
	}
	if found {
		return changed, nil
	}
	return true, AddrReplace(link, expect)
}

func AddrReplace(link netlink.Link, addr *netlink.Addr) error {
	cmd := fmt.Sprintf("ip addr replace %s dev %s", addr.IPNet.String(), link.Attrs().Name)
	err := netlink.AddrReplace(link, addr)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

func LinkSetName(link netlink.Link, name string) error {
	cmd := fmt.Sprintf("ip link set %s name %s", link.Attrs().Name, name)
	err := netlink.LinkSetName(link, name)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

func NetlinkFamily(ip net.IP) int {
	if ip.To4() == nil {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func AddrDel(link netlink.Link, addr *netlink.Addr) error {
	cmd := fmt.Sprintf("ip addr del %s dev %s", addr.IPNet.String(), link.Attrs().Name)
	err := netlink.AddrDel(link, addr)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

// FindIPRule look up ip rules in config
func FindIPRule(rule *netlink.Rule) ([]netlink.Rule, error) {
	var filterMask uint64
	family := netlink.FAMILY_V4

	if rule.Src == nil && rule.Dst == nil && rule.OifName == "" {
		return nil, errors.New("both src and dst is nil")
	}

	if rule.Src != nil {
		filterMask = filterMask | netlink.RT_FILTER_SRC
		family = NetlinkFamily(rule.Src.IP)
	}
	if rule.Dst != nil {
		filterMask = filterMask | netlink.RT_FILTER_DST
		family = NetlinkFamily(rule.Dst.IP)
	}
	if rule.OifName != "" {
		filterMask = filterMask | netlink.RT_FILTER_OIF
		family = netlink.FAMILY_V4
	}

	if rule.Priority >= 0 {
		filterMask = filterMask | netlink.RT_FILTER_PRIORITY
	}
	return netlink.RuleListFiltered(family, rule, filterMask)
}

func RuleDel(rule *netlink.Rule) error {
	cmd := fmt.Sprintf("ip rule del %s", rule.String())
	err := netlink.RuleDel(rule)
	if err != nil {
		rule.IifName = ""
		rule.OifName = ""

		err = netlink.RuleDel(rule)
		if err != nil {
			return fmt.Errorf("error %s, %w", cmd, err)
		}
	}
	return nil
}

func EnsureNeigh(neigh *netlink.Neigh) (bool, error) {
	var neighs []netlink.Neigh
	var err error

	neighs, err = netlink.NeighList(neigh.LinkIndex, netlink.FAMILY_V4)

	if err != nil {
		return false, err
	}
	found := false
	for _, n := range neighs {
		if n.IP.Equal(neigh.IP) && n.HardwareAddr.String() == neigh.HardwareAddr.String() {
			found = true
			break
		}
	}
	if !found {
		return true, NeighSet(neigh)
	}
	return false, err
}

func NeighSet(neigh *netlink.Neigh) error {
	cmd := fmt.Sprintf("ip neigh replace %s", neigh.String())
	err := netlink.NeighSet(neigh)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

// EnsureLinkUp set link up,return changed and err
func EnsureLinkUp(link netlink.Link) (bool, error) {
	if link.Attrs().Flags&net.FlagUp != 0 {
		return false, nil
	}
	return true, LinkSetUp(link)
}

func LinkSetUp(link netlink.Link) error {
	cmd := fmt.Sprintf("ip link set %s up", link.Attrs().Name)
	err := netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

// EnsureRoute will call ip route replace if route is not found
func EnsureRoute(expected *netlink.Route) (bool, error) {
	routes, err := FoundRoutes(expected)
	if err != nil {
		return false, fmt.Errorf("error list expected: %v", err)
	}
	if len(routes) > 0 {
		return false, nil
	}

	return true, RouteReplace(expected)
}

// FoundRoutes look up routes
func FoundRoutes(expected *netlink.Route) ([]netlink.Route, error) {
	family := NetlinkFamily(expected.Dst.IP)
	routeFilter := netlink.RT_FILTER_DST
	if expected.Dst == nil {
		return nil, fmt.Errorf("dst in route expect not nil")
	}
	find := *expected

	if find.Dst.String() == "::/0" || find.Dst.String() == "0.0.0.0/0" {
		find.Dst = nil
	}
	if find.LinkIndex > 0 {
		routeFilter = routeFilter | netlink.RT_FILTER_OIF
	}
	if find.Scope > 0 {
		routeFilter = routeFilter | netlink.RT_FILTER_SCOPE
	}
	if find.Gw != nil {
		routeFilter = routeFilter | netlink.RT_FILTER_GW
	}
	if find.Table > 0 {
		routeFilter = routeFilter | netlink.RT_FILTER_TABLE
	}
	return netlink.RouteListFiltered(family, &find, routeFilter)
}

func RouteReplace(route *netlink.Route) error {
	cmd := fmt.Sprintf("ip route replace %s", route.String())
	err := netlink.RouteReplace(route)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}

func EnsureIPRule(expected *netlink.Rule) (bool, error) {
	changed := false

	// 1. clean exist rules if needed
	ruleList, err := FindIPRule(expected)
	if err != nil {
		return false, err
	}
	found := false
	for _, rule := range ruleList {
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
			changed = true
			err = RuleDel(&rule)
			if err != nil {
				return changed, err
			}
		} else {
			found = true
		}
	}
	if found {
		return changed, nil
	}
	return true, RuleAdd(expected)
}

func RuleAdd(rule *netlink.Rule) error {
	cmd := fmt.Sprintf("ip rule add %s", rule.String())
	err := netlink.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("error %s, %w", cmd, err)
	}
	return nil
}
