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
	defaultListenAddress  = ":8080"
	defaultHealthzAddress = ":30048"
	defaultLogDir         = "/var/log/raptor-coordinator.log"
)

// ServerOption is the main context object for the controller manager.
type ServerOption struct {
	EnableLeaderElection bool
	EnableMetrics        bool
	ListenAddress        string
	EnableHealthz        bool
	// HealthzBindAddress is the IP address and port for the health check server to serve on
	// defaulting to :11888
	HealthzBindAddress string
	LogFileDir         string
	OpenStackOption    OpenStackOption
}

type OpenStackOption struct {
	InstanceSubnetIDs         []string
	ProjectID                 string
	SecurityGroupID           string
	AutoCreateRPNSubnetPrefix string
}

// NewServerOption creates a new CMServer with a default config.
func NewServerOption() *ServerOption {
	return &ServerOption{}
}

// AddFlags adds flags for a specific CMServer to the specified FlagSet.
func (s *ServerOption) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&s.EnableLeaderElection, "leader-elect", true,
		"Start a leader election client and gain leadership before "+
			"executing the main loop. Enable this when running replicated vc-scheduler for high availability; it is enabled by default")
	fs.StringVar(&s.ListenAddress, "listen-address", defaultListenAddress, "The address to listen on for HTTP requests.")
	fs.StringVar(&s.LogFileDir, "log-dir", defaultLogDir, "The address to listen on for HTTP requests.")

	fs.StringVar(&s.HealthzBindAddress, "healthz-address", defaultHealthzAddress, "The address to listen on for the health check server.")
	fs.BoolVar(&s.EnableHealthz, "enable-healthz", false, "Enable the health check; it is false by default")
	fs.BoolVar(&s.EnableMetrics, "enable-metrics", false, "Enable the metrics function; it is false by default")
	fs.StringVar(&s.OpenStackOption.ProjectID, "openstack-project-id", "", "Openstack project ID; it is the cluster's project ID.")
	fs.StringSliceVar(&s.OpenStackOption.InstanceSubnetIDs, "openstack-instance-subnet-ids", []string{}, "Openstack instance subnet ID; it is the cluster's instance subnet ID, accept string slice.")
	fs.StringVar(&s.OpenStackOption.AutoCreateRPNSubnetPrefix, "auto-create-rpn-subnet-prefix", "raptor", "Subnet name prefix for automatically created RaptorPodNetwork resources ")
}

func (s *ServerOption) InitFlags() {
	pflag.CommandLine.SetNormalizeFunc(k8sFlag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goFlag.CommandLine)
	pflag.Parse()
}

func (s *ServerOption) PrintFlags(log *base.Log) {
	pflag.VisitAll(func(flag *pflag.Flag) {
		log.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})
}
