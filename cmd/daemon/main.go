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
	"github.com/easystack/raptor/cmd/daemon/option"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/daemon"
	"github.com/easystack/raptor/pkg/utils"
	"github.com/spf13/pflag"
)

func main() {

	daemonOption := option.NewDaemonOption()
	daemonOption.AddFlags(pflag.CommandLine)
	daemonOption.InitFlags()

	base.InitializeBinaryLog(daemonOption.LogFileDir)
	log := base.NewLog()
	daemonOption.PrintFlags(&log)

	ctx := utils.SetupSignalContext()

	d := daemon.NewDaemon(ctx, daemonOption)
	d.Start(ctx)

}
