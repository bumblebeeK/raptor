package utils

import (
	"errors"
	"fmt"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/rpc"
	"github.com/vishvananda/netlink"
	"math/big"
	"net"
	"syscall"
)

const maxNetworkCardPerNode = 5

func CalculateAvailableAddress(startIP, endIP string) (int64, error) {
	// 将字符串形式的 IP 地址转换为 IP 对象
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()

	if start == nil || end == nil {
		return 0, errors.New("start ip address or end ip address invalid")
	}

	// 计算 IP 地址的整数表示
	startInt := big.NewInt(0).SetBytes(start)
	endInt := big.NewInt(0).SetBytes(end)

	// 计算可用 IP 地址数量
	total := new(big.Int).Sub(endInt, startInt)
	available := total.Int64() - 1 // 减去网络地址

	return available, nil
}

func AllocateVlanID(ids []int) int {
	ans := 101
	for i, id := range ids {
		if ans == id {
			ans++
			continue
		}
		if i == len(ids)-1 {
			break
		}
	}
	return ans
}

func GetNetlinkByMac(macAddr net.HardwareAddr) (error, netlink.Link) {
	var targetLink netlink.Link

	linkList, err := netlink.LinkList()

	if err != nil {
		return fmt.Errorf("get netlink list error: %v", err), nil
	}

	for _, link := range linkList {
		if link.Attrs().HardwareAddr.String() == macAddr.String() {
			targetLink = link
			break
		}
	}

	if targetLink == nil {
		return netlink.LinkNotFoundError{}, nil
	}
	return nil, targetLink
}

func GetNetlinkByVlan(vlanId int, masterLink netlink.Link) (error, netlink.Link) {

	linkList, err := netlink.LinkList()

	if err != nil {
		return fmt.Errorf("error getting netlink list: %v", err), nil
	}

	for _, link := range linkList {
		if vlanIf, ok := link.(*netlink.Vlan); ok {
			if vlanIf.VlanId == vlanId && vlanIf.ParentIndex == masterLink.Attrs().Index {
				return nil, vlanIf
			}
		}
	}

	return netlink.LinkNotFoundError{}, nil
}

func GetRouteTableID(link netlink.Link) int {
	return link.Attrs().Index + 1000
}

func SetUpNewNetworkCard(networkCard types.NetworkCard, pool types.IPPool) error {

	macAddr, err := net.ParseMAC(networkCard.GetMacAddress())
	if err != nil {
		return fmt.Errorf("failed to parse MAC address,error: %w", err)
	}
	err, link := GetNetlinkByMac(macAddr)
	if err != nil {
		return fmt.Errorf("get link by mac error: %w", err)
	}

	if networkCard.GetTrunkId() == "" {
		tableID := GetRouteTableID(link)
		// TODO support IPv6
		dst := &net.IPNet{IP: net.ParseIP(pool.GatewayIPv4), Mask: net.CIDRMask(32, 32)}
		if link.Attrs().Flags&net.FlagUp == 0 {
			err = LinkSetUp(link)
			if err != nil {
				return err
			}
		}
		err = AddSubnetRoute(dst, link.Attrs().Index, tableID, net.ParseIP(pool.GatewayIPv4))
		if err != nil {
			return fmt.Errorf("failed to add route for networkCard %s, error is %s", networkCard.GetResourceId(), err)
		}
		_, subnetCIDR, _ := net.ParseCIDR(pool.SubnetCidr)

		err = addSubnetRule(link, tableID, networkCard.GetIPSet().IPv4, subnetCIDR)
		if err != nil {
			return fmt.Errorf("failed to add route to network card, error is %s", err)
		}

		// we do not let the network manager take over network cards other than the main network card,
		// so we need to manually add the address
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: subnetCIDR.IP, Mask: net.CIDRMask(32, 32)}}
		err = netlink.AddrAdd(link, addr)
		if err != nil && err != syscall.EEXIST {
			return fmt.Errorf("failed to add addr to network card, error is %s", err)
		}
	}

	err = DisableRpFilter(link.Attrs().Name)

	if err != nil {
		return fmt.Errorf("failed to disable raptor, error is %s", err)
	}

	return nil
}

func TearDownNetworkCard(networkCard *rpc.NetworkCard, gatewayIP string) error {

	macAddr, err := net.ParseMAC(networkCard.GetMAC())
	if err != nil {
		return fmt.Errorf("failed to parse MAC address: %v", err)
	}

	err, link := GetNetlinkByMac(macAddr)
	if err != nil {
		return fmt.Errorf("error getting netlink by mac: %v", err)
	}

	tableID := GetRouteTableID(link)

	directRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.ParseIP(gatewayIP),
			Mask: net.CIDRMask(32, 32),
		},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Protocol:  syscall.RTPROT_KERNEL,
		Table:     tableID,
	}

	err = netlink.RouteDel(directRoute)
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("error deleting route: %v", err)
	}

	defaultRoute := &netlink.Route{
		Protocol:  syscall.RTPROT_KERNEL,
		Table:     tableID,
		LinkIndex: link.Attrs().Index,
		Gw:        net.ParseIP(gatewayIP),
		Dst:       nil,
	}

	err = netlink.RouteDel(defaultRoute)

	if err != nil && err != syscall.ENODATA {
		return fmt.Errorf("error deleting default route: %v", err)
	}

	return nil
}
