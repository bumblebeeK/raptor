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

package openstack

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/easystack/raptor/cmd/coordinator/option"
	"github.com/easystack/raptor/pkg/base"

	"github.com/easystack/raptor/pkg/utils"
	"github.com/easystack/raptor/rpc"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/attachinterfaces"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/availabilityzones"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/attributestags"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/trunks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"
)

var log = base.NewLogWithField("subsys", "openstack-client")

const (
	VMInterfaceName         = "raptor-vm-port"
	VMTrunkInterfaceName    = "raptor-vm-trunk-parent"
	VMTrunkName             = "raptor-trunk"
	PodInterfaceName        = "raptor-pod-port"
	PodSubPortInterfaceName = "raptor-sub-port"

	VMDeviceOwner  = "compute:"
	PodDeviceOwner = "network:secondary"

	DefaultClientTimeout = 60

	RaptorSubnetPrefix = "raptor"
)

type Client struct {
	neutronV2  *gophercloud.ServiceClient
	novaV2     *gophercloud.ServiceClient
	keystoneV3 *gophercloud.ServiceClient

	azs     []string
	subnets map[string]*rpc.Subnet

	projectID                 string
	instanceSubnetIDSet       SubnetIDSet
	securityGroupID           string
	autoCreateRPNSubnetPrefix string
}

type SubnetIDSet map[string]struct{}

func NewClient(option *option.OpenStackOption) (*Client, error) {
	provider, err := newProviderClientOrDie(false, DefaultClientTimeout)
	if err != nil {
		return nil, err
	}
	domainTokenProvider, err := newProviderClientOrDie(true, DefaultClientTimeout)
	if err != nil {
		return nil, err
	}

	netV2, err := newNetworkV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	computeV2, err := newComputeV2ClientOrDie(provider)
	if err != nil {
		return nil, err
	}

	identV3, err := newIdentityV3ClientOrDie(domainTokenProvider)
	if err != nil {
		return nil, err
	}

	c := &Client{
		neutronV2:           netV2,
		novaV2:              computeV2,
		keystoneV3:          identV3,
		projectID:           option.ProjectID,
		securityGroupID:     option.SecurityGroupID,
		instanceSubnetIDSet: SubnetIDSet{},
	}

	if option.AutoCreateRPNSubnetPrefix != "" {
		c.autoCreateRPNSubnetPrefix = option.AutoCreateRPNSubnetPrefix
	} else {
		c.autoCreateRPNSubnetPrefix = RaptorSubnetPrefix
	}

	for _, subnetID := range option.InstanceSubnetIDs {
		c.instanceSubnetIDSet[subnetID] = struct{}{}
	}

	return c, nil

}

func newProviderClientOrDie(domainScope bool, timeout int) (*gophercloud.ProviderClient, error) {
	opt, err := openstack.AuthOptionsFromEnv()
	if err != nil {
		return nil, err
	}
	// with OS_PROJECT_NAME in env, AuthOptionsFromEnv return project scope token
	// which can not list projects, we need a domain scope token here
	if domainScope {
		opt.TenantName = ""
		opt.Scope = &gophercloud.AuthScope{
			DomainName: os.Getenv("OS_DOMAIN_NAME"),
		}
	}

	p, err := openstack.AuthenticatedClient(opt)
	if err != nil {
		return nil, err
	}
	p.HTTPClient = http.Client{
		Transport: http.DefaultTransport,
		Timeout:   time.Second * time.Duration(timeout),
	}

	p.ReauthFunc = func() error {
		newProv, err := openstack.AuthenticatedClient(opt)
		if err != nil {
			return err
		}
		p.CopyTokenFrom(newProv)
		return nil
	}
	return p, nil
}

// newComputeV2ClientOrDie Create a ComputeV2 service client using the AKSK provider
func newComputeV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewComputeV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func newIdentityV3ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewIdentityV3(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func newNetworkV2ClientOrDie(p *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewNetworkV2(p, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}
	return client, nil
}

// parseNetworkCard parses an ecs.NetworkInterface as returned by the ecs service API,
// converts it into a *rpc.NetworkCard object
func (c *Client) parseNetworkCard(port *ports.Port, ip2pid map[string]string,
	pid2ip map[string]struct {
		ip       string
		pool     string
		mac      string
		subnetId string
	}) (instanceID string, networkCard *rpc.NetworkCard, err error) {
	if len(port.FixedIPs) == 0 {
		log.Errorf(" Failed to parse NetworkCard %+v, because that fixedIPs is empty.", port)
		return "", nil, fmt.Errorf("FixedIPs of port is empty")
	}

	subnetID := port.FixedIPs[0].SubnetID
	networkCard = &rpc.NetworkCard{
		ID: port.ID,
		IPSet: &rpc.IPSet{
			IPv4: port.FixedIPs[0].IPAddress,
		},
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		NetworkId:      port.NetworkID,
		SubnetId:       subnetID,
		Tags:           port.Tags,
	}

	subnet, ok := c.subnets[subnetID]

	if ok {
		if subnet.CIDR != nil {
			networkCard.CIDR = subnet.CIDR
		}

		networkCard.Pool = subnet.Name
	}

	if !ok {
		return "", nil, fmt.Errorf("parse NetworkCard failed,subnet ID: %s not found, port id is %s, device-id is %s", subnetID, port.ID, port.DeviceID)
	}
	ipSets := map[string]*rpc.VPCIP{}

	if strings.HasPrefix(port.Name, VMTrunkInterfaceName) {
		if port.TrunkDetails.TrunkID != "" {
			networkCard.TrunkID = port.TrunkDetails.TrunkID
			networkCard.IsTrunk = true
			for _, subPort := range port.TrunkDetails.SubPorts {
				if info, exist := pid2ip[subPort.PortID]; exist {
					ipSets[info.ip] = &rpc.VPCIP{
						IPSet: &rpc.IPSet{
							IPv4: info.ip,
						},
						PortId:     subPort.PortID,
						Vid:        int32(subPort.SegmentationID),
						MACAddress: info.mac,
						Pool:       info.pool,
						SubnetId:   info.subnetId,
					}
				} else {
					log.Errorf("Failed to find pod IP of port %s when parse network card", subPort.PortID)
				}
			}
		}
	} else {
		for _, pair := range port.AllowedAddressPairs {
			ipSets[pair.IPAddress] = &rpc.VPCIP{
				IPSet:             &rpc.IPSet{IPv4: pair.IPAddress},
				PortId:            ip2pid[pair.IPAddress],
				NetworkCardPortId: port.ID,
				Pool:              networkCard.Pool,
				SubnetId:          networkCard.SubnetId,
				MACAddress:        networkCard.MAC,
			}
		}
	}

	networkCard.VPCIPs = ipSets

	log.Infof("Parsed network card %+v", networkCard)
	log.Infof("Parsed network card %s trunkid %s", networkCard.IPSet.IPv4, networkCard.TrunkID)

	return port.DeviceID, networkCard, nil
}

func (c *Client) calculatePortCount(ip2pid map[string]string, ip2ips map[string]struct {
	ip       string
	pool     string
	mac      string
	subnetId string
}, subnetId string, pool string) (int, error) {
	var err error
	var portCount int

	var curAz []ports.Port
	opts := ports.ListOpts{
		ProjectID: c.projectID,
	}
	if subnetId != "" {
		opts.FixedIPs = []ports.FixedIPOpts{
			{
				SubnetID: subnetId,
			},
		}
	}

	err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
		curAz, err = ports.ExtractPorts(page)
		if err != nil {
			return false, err
		}

		return true, nil
	})

	for _, port := range curAz {
		portCount++

		if len(port.FixedIPs) == 0 {
			log.Warnf("Port %s has no fix ips.", port.ID)
			continue
		}

		ip2pid[port.FixedIPs[0].IPAddress] = port.ID
		ip2ips[port.ID] = struct {
			ip       string
			pool     string
			mac      string
			subnetId string
		}{ip: port.FixedIPs[0].IPAddress, pool: pool, mac: port.MACAddress, subnetId: subnetId}
	}

	return portCount, nil
}

func (c *Client) describeNetworkInterfaces() ([]ports.Port, error) {
	var result []ports.Port
	var err error

	for _, az := range c.azs {
		var curAz []ports.Port
		opts := ports.ListOpts{
			ProjectID:   c.projectID,
			DeviceOwner: az,
		}

		err = ports.List(c.neutronV2, opts).EachPage(func(page pagination.Page) (bool, error) {
			curAz, err = ports.ExtractPorts(page)
			if err != nil {
				return false, err
			}

			return true, nil
		})
		for _, port := range curAz {
			result = append(result, port)
		}
	}

	return result, nil
}

// GetInstances returns the list of all instances including their NetworkCards as
// instanceMap
func (c *Client) GetInstances(ip2pid map[string]string,
	pid2ip map[string]struct {
		ip       string
		pool     string
		mac      string
		subnetId string
	}, defaultNetworkCardIP2InstanceIDMap map[string]string, instances map[string]*rpc.Instance) error {
	pool2NetworkCardsCount := map[string][]string{}

	var networkInterfaces []ports.Port
	var err error

	c.azs, err = c.describeAZs()
	if err != nil {
		return err
	}

	networkInterfaces, err = c.describeNetworkInterfaces()
	if err != nil {
		return err
	}

	for _, iFace := range networkInterfaces {
		if strings.HasPrefix(iFace.DeviceOwner, VMDeviceOwner) {
			instanceId, networkCard, err := c.parseNetworkCard(&iFace, ip2pid, pid2ip)
			if err != nil {
				continue
			}

			if instanceId != "" {
				if _, exist := instances[instanceId]; !exist {
					instances[instanceId] = &rpc.Instance{NetworkCards: map[string]*rpc.NetworkCard{}}
				}
				instances[instanceId].NetworkCards[networkCard.GetID()] = networkCard
			}
			ip2pid[networkCard.GetIPSet().GetIPv4()] = networkCard.GetID()
			pool2NetworkCardsCount[networkCard.GetPool()] = append(pool2NetworkCardsCount[networkCard.GetPool()], instanceId)

			// establish mapping between main network card IP and instanceID
			if _, exist := c.instanceSubnetIDSet[networkCard.GetSubnetId()]; exist {
				defaultNetworkCardIP2InstanceIDMap[networkCard.GetIPSet().GetIPv4()] = instanceId
			}
		}
	}

	return nil
}

// describeSubnets lists all subnets
func (c *Client) describeSubnets() ([]subnets.Subnet, error) {
	opts := subnets.ListOpts{
		ProjectID: c.projectID,
	}
	pages, err := subnets.List(c.neutronV2, opts).AllPages()
	if err != nil {
		return nil, err
	}
	allSubnets, _ := subnets.ExtractSubnets(pages)
	return allSubnets, nil
}

// GetSubnets returns all subnets as a subnetMap
func (c *Client) GetSubnets(ip2pid map[string]string, subnetMap map[string]*rpc.Subnet) (err error, id2ip map[string]struct {
	ip       string
	pool     string
	mac      string
	subnetId string
}) {
	subnetList, err := c.describeSubnets()
	if err != nil {
		return err, nil
	}

	id2ip = map[string]struct {
		ip       string
		pool     string
		mac      string
		subnetId string
	}{}

	for _, s := range subnetList {
		_, isDefault := c.instanceSubnetIDSet[s.ID]
		if !(isDefault || strings.HasPrefix(s.Name, c.autoCreateRPNSubnetPrefix)) {
			continue
		}

		if len(s.AllocationPools) == 0 {
			continue
		}

		pool := utils.NormalizeCRName(s.Name)

		createdPortCount, err := c.calculatePortCount(ip2pid, id2ip, s.ID, pool)
		if err != nil {
			return err, nil
		}

		count, err := utils.CalculateAvailableAddress(s.AllocationPools[0].Start, s.AllocationPools[0].End)
		if err != nil {
			continue
		}

		subnet := &rpc.Subnet{
			ID:        s.ID,
			NetworkID: s.NetworkID,
			CIDR: &rpc.IPSet{
				IPv4: s.CIDR,
			},
			Name:            pool,
			AllocationCount: count,
			AllocatedCount:  int64(createdPortCount),
			GatewayIP: &rpc.IPSet{
				IPv4: s.GatewayIP,
			},
		}

		if _, isInstance := c.instanceSubnetIDSet[s.ID]; isInstance {
			subnet.IsDefault = true
		}

		subnetMap[subnet.ID] = subnet
	}
	c.subnets = subnetMap

	return nil, id2ip
}

// GetAzs retrieves azlist
func (c *Client) GetAzs() ([]string, error) {
	return c.describeAZs()
}

// PortCreateOpts options to create port
type PortCreateOpts struct {
	Name           string
	NetworkID      string
	SubnetID       string
	IPAddress      string
	ProjectID      string
	SecurityGroups *[]string
	DeviceID       string
	DeviceOwner    string
	Tags           string
	Description    string
}

type FixedIPOpt struct {
	SubnetID        string `json:"subnet_id,omitempty"`
	IPAddress       string `json:"ip_address,omitempty"`
	IPAddressSubstr string `json:"ip_address_subdir,omitempty"`
}
type FixedIPOpts []FixedIPOpt

// create neutron port for both CreateNetworkInterface and AssignIpAddress
func (c *Client) createPort(opt PortCreateOpts) (*rpc.NetworkCard, error) {
	copts := ports.CreateOpts{
		Name:           opt.Name,
		NetworkID:      opt.NetworkID,
		DeviceOwner:    opt.DeviceOwner,
		DeviceID:       opt.DeviceID,
		ProjectID:      opt.ProjectID,
		SecurityGroups: opt.SecurityGroups,
		Description:    opt.Description,
		FixedIPs: FixedIPOpts{
			{
				SubnetID:  opt.SubnetID,
				IPAddress: opt.IPAddress,
			},
		},
	}

	port, err := ports.Create(c.neutronV2, copts).Extract()
	if err != nil {
		return nil, err
	}

	NetworkCard := &rpc.NetworkCard{
		ID: port.ID,
		IPSet: &rpc.IPSet{
			IPv4: port.FixedIPs[0].IPAddress,
		},
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		NetworkId:      port.NetworkID,
		SubnetId:       opt.SubnetID,
	}

	return NetworkCard, nil
}

// CreateNetworkInterface creates an NetworkCard with the given parameters
func (c *Client) CreateNetworkInterface(instanceId, networkId, subnetId string, isTrunk bool) (*rpc.NetworkCard, error) {
	var networkCard *rpc.NetworkCard
	var err error
	log.Infof("Ready to create network interface, instance id: %s, networkId: %s, subnetId: %s, isTrunk: %v", instanceId, networkId, subnetId, isTrunk)
	if !isTrunk {
		opt := PortCreateOpts{
			Name:      fmt.Sprintf(VMInterfaceName+"-%s", utils.RandomString(10)),
			NetworkID: networkId,
			// SubnetID:    subnetId,
			DeviceOwner: fmt.Sprintf(VMDeviceOwner+"%s", instanceId),
			ProjectID:   c.projectID,
		}

		// use specified sgs to create vm NICs
		if c.securityGroupID != "" {
			sgs := strings.Split(strings.ReplaceAll(c.securityGroupID, " ", ""), ",")
			opt.SecurityGroups = &sgs
		}

		networkCard, err = c.createPort(opt)
		if err != nil {
			return nil, err
		}
	} else {
		opt := PortCreateOpts{
			Name:      fmt.Sprintf(VMTrunkInterfaceName+"-%s", utils.RandomString(10)),
			NetworkID: networkId,
			// SubnetID:    subnetId,
			DeviceOwner: fmt.Sprintf(VMDeviceOwner+"%s", instanceId),
			ProjectID:   c.projectID,
			Description: "Trunk created by raptor cni",
		}
		networkCard, err = c.createPort(opt)
		if err != nil {
			return nil, err
		}

		adminStateUp := true

		trunkCreateOpts := trunks.CreateOpts{
			Name:         fmt.Sprintf(VMTrunkName+"-%s", utils.RandomString(10)),
			Description:  "Trunk created by raptor cni",
			AdminStateUp: &adminStateUp,
			PortID:       networkCard.ID,
		}

		trunkId, err := c.createTrunk(trunkCreateOpts)
		if err != nil {
			err1 := c.deletePort(networkCard.ID)
			if err1 != nil {
				log.Errorf("Error deleting trunk parent port %s", networkCard.ID)
			}
			return nil, err
		}
		networkCard.IsTrunk = true
		networkCard.TrunkID = trunkId
		networkCard.SubnetId = subnetId
	}

	return networkCard, nil
}

// DeleteNetworkInterface deletes an NetworkCardA with the specified ID
func (c *Client) DeleteNetworkInterface(NetworkCardID string) error {
	r := ports.Delete(c.neutronV2, NetworkCardID)
	return r.ExtractErr()
}

// DeleteTrunk deletes a Trunk with the specified ID
func (c *Client) DeleteTrunk(trunkID string) error {
	r := trunks.Delete(c.neutronV2, trunkID)
	return r.ExtractErr()
}

// AddTagToNetworkInterface add tag to port
func (c *Client) AddTagToNetworkInterface(networkCardID string, tags string) error {
	return attributestags.Add(c.neutronV2, "ports", networkCardID, tags).ExtractErr()
}

// GetVPCs retrieves and returns all VPCs
func (c *Client) GetVPCs() (map[string]struct{}, error) {
	vpcs := map[string]struct{}{}

	vpcList, err := c.describeVPCs()
	if err != nil {
		return nil, err
	}

	for _, v := range vpcList {
		vpcs[v.ID] = struct{}{}
	}

	return vpcs, nil
}

// describeAZs lists all AZs
func (c *Client) describeAZs() ([]string, error) {
	allPages, err := availabilityzones.List(c.novaV2).AllPages()
	if err != nil {
		return nil, err
	}
	availabilityZoneInfo, err := availabilityzones.ExtractAvailabilityZones(allPages)
	if err != nil {
		return nil, err
	}
	var azs []string

	for _, zoneInfo := range availabilityZoneInfo {
		if zoneInfo.ZoneName != "internal" {
			azs = append(azs, VMDeviceOwner+zoneInfo.ZoneName)
		}
	}
	return azs, nil
}

// describeVPCs lists all VPCs
func (c *Client) describeVPCs() ([]networks.Network, error) {
	opts := networks.ListOpts{
		ProjectID: c.projectID,
	}

	pages, err := networks.List(c.neutronV2, opts).AllPages()
	if err != nil {
		return nil, err
	}
	allNetworks, _ := networks.ExtractNetworks(pages)
	return allNetworks, nil
}

// AssignPrivateIPAddresses assigns the specified number of secondary IP
// return allocated IPs
func (c *Client) AssignPrivateIPAddresses(networkCardId, networkCardMacAddr, networkId, subnetId, pool string, resourceId string) (*rpc.VPCIP, error) {

	var address *rpc.VPCIP
	var allowedAddressPairs []ports.AddressPair

	opt := PortCreateOpts{
		Name:        fmt.Sprintf(PodInterfaceName+"-%s", utils.RandomString(10)),
		NetworkID:   networkId,
		SubnetID:    subnetId,
		DeviceID:    networkCardId,
		DeviceOwner: PodDeviceOwner,
		ProjectID:   c.projectID,
	}
	p, err := c.createPort(opt)
	if err != nil {
		return address, err
	}

	address = &rpc.VPCIP{
		MACAddress: networkCardMacAddr,
		IPSet: &rpc.IPSet{
			IPv4: p.GetIPSet().GetIPv4(),
		},
		PortId:   p.GetID(),
		Pool:     pool,
		SubnetId: subnetId,
	}
	allowedAddressPairs = append(allowedAddressPairs, ports.AddressPair{
		IPAddress:  p.IPSet.IPv4,
		MACAddress: networkCardMacAddr,
	})

	err = c.addPortAllowedAddressPairs(networkCardId, allowedAddressPairs)
	if err != nil {
		log.Errorf("######## Failed to update port allowed-address-pairs with error: %+v", err)
		err = c.deletePort(p.ID)
		if err != nil {
			log.Errorf("######## Failed to rollback to delete port with error: %+v", err)
		}
	}

	return address, nil
}

func (c *Client) AssignSubPortToTrunk(trunkId string, networkId, subnetId string, pool string, resourceId string) (*rpc.VPCIP, error) {
	var err error
	var podIP *rpc.VPCIP
	var port *rpc.NetworkCard

	trunk, err := trunks.Get(c.neutronV2, trunkId).Extract()

	if err != nil {
		return nil, fmt.Errorf("get trunk error: %s", err)
	}

	if resourceId != "" {
		p, err := c.getPort(resourceId)
		if err != nil {
			return nil, fmt.Errorf("failed to get port %s, error: %s", resourceId, err)
		}
		if p.BindingProfile.ParentName != "" {
			return nil, fmt.Errorf("this port is belong to an other port: %s", p.BindingProfile.ParentName)
		}

		port = parsePort(p)
	} else {
		opt := PortCreateOpts{
			Name:      fmt.Sprintf(PodSubPortInterfaceName+"-%s", utils.RandomString(10)),
			NetworkID: networkId,
			SubnetID:  subnetId,
			ProjectID: c.projectID,
		}

		port, err = c.createPort(opt)
		if err != nil {
			return nil, fmt.Errorf("failed to create port, error: %s", err)
		}
	}

	var allocatedSegmentationIDs []int
	for _, subPort := range trunk.Subports {
		allocatedSegmentationIDs = append(allocatedSegmentationIDs, subPort.SegmentationID)
	}

	vid := utils.AllocateVlanID(allocatedSegmentationIDs)

	_, err = trunks.AddSubports(c.neutronV2, trunkId, trunks.AddSubportsOpts{
		Subports: []trunks.Subport{
			{
				SegmentationType: "vlan",
				SegmentationID:   vid,
				PortID:           port.ID,
			},
		},
	}).Extract()

	if err != nil {
		innerErr := c.deletePort(port.ID)
		if innerErr != nil {
			log.Errorf("Delete port %s error: %s when adding sub port for trunk %s failed.", port.ID, innerErr.Error(), trunkId)
		}
		return nil, err
	}

	podIP = &rpc.VPCIP{
		MACAddress: port.GetMAC(),
		IPSet: &rpc.IPSet{
			IPv4: port.GetIPSet().GetIPv4(),
		},
		PortId:   port.GetID(),
		Vid:      int32(vid),
		TrunkId:  trunk.ID,
		Pool:     pool,
		SubnetId: subnetId,
	}

	return podIP, err
}

// AttachNetworkInterface attaches a previously created NetworkCard to an instance
func (c *Client) AttachNetworkInterface(instanceID, NetworkCardID string) error {
	log.Infof("######## Do attach network interface: %s to vm: %s.", NetworkCardID, instanceID)

	createOpts := attachinterfaces.CreateOpts{
		PortID: NetworkCardID,
	}
	_, err := attachinterfaces.Create(c.novaV2, instanceID, createOpts).Extract()
	if err != nil {
		return err
	}

	return nil
}

// getPort get neutron port
func (c *Client) getPort(id string) (*ports.Port, error) {
	port, err := ports.Get(c.neutronV2, id).Extract()
	if err != nil {
		return nil, err
	}
	if len(port.FixedIPs) == 0 {
		return nil, fmt.Errorf("no ip address found on port")
	}

	return port, nil
}

func parsePort(port *ports.Port) *rpc.NetworkCard {
	networkCard := &rpc.NetworkCard{
		ID: port.ID,
		IPSet: &rpc.IPSet{
			IPv4: port.FixedIPs[0].IPAddress,
		},
		MAC:            port.MACAddress,
		SecurityGroups: port.SecurityGroups,
		NetworkId:      port.NetworkID,
		SubnetId:       port.FixedIPs[0].SubnetID,
	}
	return networkCard
}

func (c *Client) deletePort(id string) error {
	r := ports.Delete(c.neutronV2, id)
	return r.ExtractErr()
}

func (c *Client) createTrunk(createOpts trunks.CreateOpts) (string, error) {
	trunk, err := trunks.Create(c.neutronV2, createOpts).Extract()

	if err != nil {
		return "", err
	}

	return trunk.ID, nil
}

// addPortAllowedAddressPairs to assign secondary ip address
func (c *Client) addPortAllowedAddressPairs(NetworkCardID string, pairs []ports.AddressPair) error {
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	_, err := ports.AddAllowedAddressPair(c.neutronV2, NetworkCardID, opts).Extract()
	if err != nil {
		log.Errorf("##### Failed to add allowed address pair, error is %s", err)
		return err
	}
	return nil
}

func (c *Client) UnAssignSubPortForTrunk(portId, trunkId string, deletePort bool) (err error) {
	_, err = trunks.RemoveSubports(c.neutronV2, trunkId,
		trunks.RemoveSubportsOpts{Subports: []trunks.RemoveSubport{{PortID: portId}}}).Extract()

	if err != nil {
		return err
	}

	if deletePort {
		return c.deletePort(portId)
	}
	return nil
}

// UnAssignPrivateIPAddress unAssign specified IP addresses from NetworkCard
// should not provide Primary IP
func (c *Client) UnAssignPrivateIPAddress(ipSet *rpc.IPSet, macAddr, networkCardId string, portId string, deleteResource bool) (err error) {
	var allowedAddressPairs []ports.AddressPair

	allowedAddressPairs = append(allowedAddressPairs, ports.AddressPair{
		// TODO support IPv6
		IPAddress:  ipSet.GetIPv4(),
		MACAddress: macAddr,
	})

	// TODO proton新版本中只需要调用删除port接口，这个还需要确认
	log.Infof("Try to delete port allowed-address-pairs: %+v %v", allowedAddressPairs, networkCardId)
	err = c.deletePortAllowedAddressPairs(networkCardId, allowedAddressPairs)
	if err != nil {
		log.Errorf("Update port allowed-address-pairs with error: %+v", err)
		return err
	}

	if deleteResource {
		err = c.deletePort(portId)
		if err != nil {
			log.Errorf("######## Failed to delete port with error: %+v", err)
			return err
		}
	}

	return nil
}

// deletePortAllowedAddressPairs to assign secondary ip address
func (c *Client) deletePortAllowedAddressPairs(networkCardID string, pairs []ports.AddressPair) error {
	if len(pairs) == 0 {
		return nil
	}
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	_, err := ports.RemoveAllowedAddressPair(c.neutronV2, networkCardID, opts).Extract()
	if err != nil {
		return err
	}
	return nil
}

// updatePortAllowedAddressPairs to assign secondary ip address
func (c *Client) updatePortAllowedAddressPairs(networkCardID string, pairs []ports.AddressPair) error {
	opts := ports.UpdateOpts{
		AllowedAddressPairs: &pairs,
	}
	_, err := ports.Update(c.neutronV2, networkCardID, opts).Extract()
	if err != nil {
		return err
	}
	return nil
}

// TransferPortFromNetworkCardAToAnotherNetworkCardB to
func (c *Client) TransferPortFromNetworkCardAToAnotherNetworkCardB(NetworkCardA, NetworkCardB, macAddress string, podIP *rpc.VPCIP) error {
	var err error
	err = c.deletePortAllowedAddressPairs(NetworkCardA, []ports.AddressPair{
		{
			IPAddress:  podIP.GetIPSet().GetIPv4(),
			MACAddress: podIP.GetMACAddress(),
		},
	})
	if err != nil {
		return err
	}

	_, err = ports.Update(c.neutronV2, podIP.GetPortId(), ports.UpdateOpts{
		DeviceID: &NetworkCardB,
	}).Extract()
	if err != nil {
		return err
	}

	err = c.addPortAllowedAddressPairs(NetworkCardB, []ports.AddressPair{
		{
			IPAddress:  podIP.GetIPSet().GetIPv4(),
			MACAddress: macAddress,
		},
	})
	if err != nil {
		return err
	}

	return nil
}
