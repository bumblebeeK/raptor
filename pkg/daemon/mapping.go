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

package daemon

import (
	"sync"

	"github.com/easystack/raptor/pkg/types"
)

// namespace2poolMap is a thread-safe map that stores the mapping from namespace to IP pool list.
type namespace2poolMap struct {
	data  map[string][]types.IPPool // Stores the mapping from namespace to IP pool list
	mutex sync.Mutex
}

// update replaces the current data with newData in a thread-safe manner.
func (n *namespace2poolMap) update(newData map[string][]types.IPPool) {
	n.mutex.Lock()
	n.data = newData
	n.mutex.Unlock() // Release the lock
}

// getNamespacePool retrieves the IP pool list for a given namespace in a thread-safe manner.
func (n *namespace2poolMap) getNamespacePool(namespace string) []types.IPPool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.data[namespace] // Return the IP pool list for the specified namespace
}

// newMapping creates and returns a new namespace2poolMap instance.
func newMapping() namespace2poolMap {
	return namespace2poolMap{
		data: make(map[string][]types.IPPool), // Initialize the data map
	}
}
