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

package option

import (
	goFlag "flag"
	"github.com/easystack/raptor/pkg/base"
	"github.com/spf13/pflag"
	k8sFlag "k8s.io/component-base/cli/flag"
)

const (
	defaultListenAddress                 = ":30081"
	defaultHealthzAddress           uint = 30028
	defaultLogDir                        = "/var/log/raptor-daemon.log"
	defaultCoordinatorServerAddress      = "coordinator.kube-system.svc:8080"
	IPStorePath                          = "/opt/cni/raptor.db"
)

// DaemonOption is the main context object for the Daemon.
type DaemonOption struct {
	EnableMetrics bool
	ListenAddress string
	EnableHealthz bool
	// HealthzBindAddress is the IP address and port for the health check server to serve on
	// defaulting to :11888
	HealthzBindAddress  uint
	LogFileDir          string
	InstanceId          string
	MaxENI              int
	MaxIPPerNetworkCard int
	TrunkSubnetId       string

	CoordinatorServerAddress string
	EnableTrunk              bool
	IPStorePath              string
}

// NewDaemonOption creates a new DaemonOption with a default config.
func NewDaemonOption() *DaemonOption {
	return &DaemonOption{}
}

func (s *DaemonOption) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.ListenAddress, "listen-address", defaultListenAddress, "The address to listen on for HTTP requests.")
	fs.UintVar(&s.HealthzBindAddress, "healthz-address", defaultHealthzAddress, "The address to listen on for the health check server.")
	fs.BoolVar(&s.EnableHealthz, "enable-healthz", false, "Enable the health check; it is false by default")
	fs.BoolVar(&s.EnableMetrics, "enable-metrics", false, "Enable the metrics function; it is false by default")
	fs.StringVar(&s.LogFileDir, "log-dir", defaultLogDir, "The address to listen on for HTTP requests.")
	fs.StringVar(&s.CoordinatorServerAddress, "coordinator-server-address", defaultCoordinatorServerAddress, "The address to connect to coordinator server.")
	fs.StringVar(&s.TrunkSubnetId, "trunk-subnet-id", "", "The subnet to create trunk parent.")
	fs.StringVar(&s.IPStorePath, "ip-store-path", "", "The subnet to create trunk parent.")
}

func (s *DaemonOption) InitFlags() {
	pflag.CommandLine.SetNormalizeFunc(k8sFlag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goFlag.CommandLine)
	pflag.Parse()
}

func (s *DaemonOption) PrintFlags(log *base.Log) {
	pflag.VisitAll(func(flag *pflag.Flag) {
		log.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})
}
