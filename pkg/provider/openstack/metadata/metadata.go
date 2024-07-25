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

package metadata

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const (
	metadataURL = "http://169.254.169.254/openstack/latest/meta_data.json"
)

type NodeInfo struct {
	UUID             string `json:"uuid"`
	Hostname         string `json:"hostname"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	AvailabilityZone string `json:"availability_zone"`
}

// GetMetadata gets metadata
func GetMetadata(ctx context.Context) (*NodeInfo, error) {

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	node := &NodeInfo{}
	err = json.Unmarshal(body, node)
	if err != nil {
		return nil, err
	}

	return node, nil
}
