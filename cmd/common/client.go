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

package common

import (
	"context"
	"fmt"
	"net"

	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/rpc"
	"google.golang.org/grpc"
)

func GetRaptorClient(ctx context.Context) (rpc.RaptorBackendClient, *grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, types.DefaultSocketPath, grpc.WithInsecure(), grpc.WithContextDialer(
		func(ctx context.Context, s string) (net.Conn, error) {
			unixAddr, err := net.ResolveUnixAddr("unix", types.DefaultSocketPath)
			if err != nil {
				return nil, fmt.Errorf("error resolve addr, %w", err)
			}
			d := net.Dialer{}
			return d.DialContext(ctx, "unix", unixAddr.String())
		}))
	if err != nil {
		return nil, nil, fmt.Errorf("error dial to raptor server %s, with error: %w", types.DefaultSocketPath, err)
	}

	client := rpc.NewRaptorBackendClient(conn)
	return client, conn, nil
}
