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
	"context"
	"time"

	cmdcommon "github.com/easystack/raptor/cmd/common"
	"github.com/easystack/raptor/rpc"
)

func getPodRecordInfo(subnetid string, pool string, namespace string) ([]*rpc.PodRecord, error) {
	client, conn, err := cmdcommon.GetRaptorClient(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelFunc()
	response, err := client.ListPodRecords(ctx, &rpc.ListPodRecordsRequest{
		SubnetId:  subnetid,
		Pool:      pool,
		Namespace: namespace,
	})

	return response.PodRecords, err
}
