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

package coordinator

import (
	"sync"

	"github.com/easystack/raptor/rpc"
)

// InstanceMap is a thread-safe map that stores the mapping from instance ID to Instance.
type InstanceMap struct {
	mutex sync.RWMutex
	data  map[string]*Instance // Map storing instance ID to Instance
}

// Instance represents an instance with its data and mutex for thread-safe access.
type Instance struct {
	mutex sync.Mutex
	data  *rpc.Instance
}

// UpdateInstances updates the instances in the map with the given new instances.
func (m *InstanceMap) UpdateInstances(instances map[string]*rpc.Instance) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for instanceID, instance := range instances {
		if _, exist := m.data[instanceID]; !exist {
			m.data[instanceID] = &Instance{data: instance}
		}
		m.data[instanceID].UpdateInstance(instance)
	}
}

// UpdateInstance updates the data of an instance.
func (i *Instance) UpdateInstance(new *rpc.Instance) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	i.data = new
}

// AcquireInstance retrieves the instance data for a given instance ID.
func (m *InstanceMap) AcquireInstance(instanceID string) *rpc.Instance {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instance, exist := m.data[instanceID]; exist {
		instance.mutex.Lock()
		defer instance.mutex.Unlock()
		return instance.data
	}

	return &rpc.Instance{}
}

// SubnetMap is a thread-safe map that stores the mapping from subnet ID to Subnet.
type SubnetMap struct {
	mutex sync.RWMutex
	data  map[string]*rpc.Subnet
}

// UpdateSubnets updates the subnets in the map with the given new subnets.
func (m *SubnetMap) UpdateSubnets(subnets map[string]*rpc.Subnet) {
	m.mutex.Lock()
	m.data = subnets
	m.mutex.Unlock()
}

// AcquireSubnet retrieves the entire subnet map.
func (m *SubnetMap) AcquireSubnet() map[string]*rpc.Subnet {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.data
}

// AcquireSubnetById retrieves the subnet data for a given subnet ID.
func (m *SubnetMap) AcquireSubnetById(id string) *rpc.Subnet {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.data[id]
}

// Ip2PidMap is a thread-safe map that stores the mapping from IP to PID.
type Ip2PidMap struct {
	mutex sync.RWMutex
	data  map[string]string // Map storing IP to PID
}

// Update updates the IP to PID mappings in the map.
func (m *Ip2PidMap) Update(Ip2Pids map[string]string) {
	m.mutex.Lock()
	m.data = Ip2Pids
	m.mutex.Unlock()
}

// InstanceNetworkCardIP2InstanceIDMap is a thread-safe map that stores the mapping from network card IP to instance ID.
type InstanceNetworkCardIP2InstanceIDMap struct {
	mutex sync.RWMutex
	data  map[string]string
}

// Update updates the network card IP to instance ID mappings in the map.
func (m *InstanceNetworkCardIP2InstanceIDMap) Update(defaultNetworkCard2InstanceIDMap map[string]string) {
	m.mutex.Lock()
	m.data = defaultNetworkCard2InstanceIDMap
	m.mutex.Unlock()
}

// AcquireInstanceID retrieves the instance ID for a given network card IP.
func (m *InstanceNetworkCardIP2InstanceIDMap) AcquireInstanceID(ip string) string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if instanceID, exist := m.data[ip]; exist {
		return instanceID
	}

	return ""
}
