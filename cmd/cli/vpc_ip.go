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

package main

import (
	"encoding/json"
	"github.com/boltdb/bolt"
	"github.com/easystack/raptor/pkg/types"
)

func getVPCIPInfo(name, subnetId string) ([]types.VPCIPImpl, error) {
	ips := []types.VPCIPImpl{}

	err := engine.View(func(tx *bolt.Tx) error {

		if name == "" {
			bytes := tx.Bucket([]byte(subnetId)).Get([]byte(name))
			card := types.VPCIPImpl{}
			err := json.Unmarshal(bytes, &card)
			if err != nil {
				return err
			}
			ips = append(ips, card)
			return nil
		}

		return tx.Bucket([]byte(networkCardBucketName)).ForEach(func(_, v []byte) error {
			ip := types.VPCIPImpl{}
			err := json.Unmarshal(v, &ip)
			if err != nil {
				return err
			}
			ips = append(ips, ip)
			return nil
		})
	})
	return ips, err
}
