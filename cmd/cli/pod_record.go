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

var recordBucketName = "record"

func getPodRecordInfo(name string) ([]types.PodRecord, error) {
	records := []types.PodRecord{}

	err := engine.View(func(tx *bolt.Tx) error {

		if name == "" {
			bytes := tx.Bucket([]byte(recordBucketName)).Get([]byte(name))
			card := types.PodRecord{}
			err := json.Unmarshal(bytes, &card)
			if err != nil {
				return err
			}
			records = append(records, card)
			return nil
		}

		return tx.Bucket([]byte(networkCardBucketName)).ForEach(func(_, v []byte) error {
			record := types.PodRecord{}
			err := json.Unmarshal(v, &record)
			if err != nil {
				return err
			}
			records = append(records, record)
			return nil
		})
	})
	return records, err
}
