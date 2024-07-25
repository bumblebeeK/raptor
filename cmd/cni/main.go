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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/alexflint/go-filemutex"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypes100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	cmdcommon "github.com/easystack/raptor/cmd/common"
	"github.com/easystack/raptor/pkg/base"
	"github.com/easystack/raptor/pkg/datapath"
	"github.com/easystack/raptor/pkg/datapath/driver"
	"github.com/easystack/raptor/pkg/types"
	"github.com/easystack/raptor/rpc"
	"github.com/vishvananda/netlink"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

var log base.Log

func main() {

	base.InitializeBinaryLog("/var/log/raptor-cni.log")
	log = base.NewLog()

	p := skel.CNIFuncs{
		Add:    cmdAdd,
		Del:    cmdDel,
		Check:  cmdCheck,
		GC:     cmdGC,
		Status: cmdStatus,
	}

	skel.PluginMainFuncs(p, version.All, "raptor vpc cni plugin")
}

func parseValueFromArgs(key, argString string) (string, error) {
	if argString == "" {
		return "", errors.New("CNI_ARGS is required")
	}
	args := strings.Split(argString, ";")
	for _, arg := range args {
		if strings.HasPrefix(arg, fmt.Sprintf("%s=", key)) {
			value := strings.TrimPrefix(arg, fmt.Sprintf("%s=", key))
			if len(value) > 0 {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("%s is required in CNI_ARGS", key)
}

func getK8sArgs(args *skel.CmdArgs) (*types.K8sArgs, error) {

	podNamespace, err := parseValueFromArgs("K8S_POD_NAMESPACE", args.Args)

	if err != nil {
		return nil, err
	}

	podName, err := parseValueFromArgs("K8S_POD_NAME", args.Args)
	if err != nil {
		return nil, err
	}

	result := types.K8sArgs{
		K8sPodName:          podName,
		K8sPodNameSpace:     podNamespace,
		K8sInfraContainerID: args.ContainerID,
	}
	return &result, nil
}

func getCmdArgs(args *skel.CmdArgs) (types.CNIAddArgs, error) {
	netConf, err := loadNetConf(args.StdinData)
	if err != nil {
		return types.CNIAddArgs{}, err
	}

	k8sArgs, err := getK8sArgs(args)
	if err != nil {
		return types.CNIAddArgs{}, err
	}

	cmdArgs := types.CNIAddArgs{
		NetConf: netConf,
		NetNS:   args.Netns,
		K8sArgs: k8sArgs,
		RawArgs: args,
	}
	return cmdArgs, nil
}

func cmdAdd(args *skel.CmdArgs) error {

	addArgs, err := getCmdArgs(args)
	ctx, cancel := context.WithTimeout(context.Background(), types.DefaultCNITimeout)
	defer cancel()

	client, conn, err := cmdcommon.GetRaptorClient(ctx)
	if err != nil {
		return fmt.Errorf("create grpc client error: %w", err)
	}
	defer conn.Close()

	result, err := doCmdAdd(ctx, client, &addArgs)
	if err != nil {
		return err
	}

	result.CNIVersion = addArgs.CNIVersion
	return cniTypes.PrintResult(result, addArgs.CNIVersion)
}

func doCmdAdd(ctx context.Context, client rpc.RaptorBackendClient, cmdArgs *types.CNIAddArgs) (*cniTypes100.Result, error) {

	var err error
	response, err := client.CreateEndpoint(ctx, &rpc.CreateEndpointRequest{
		Netns:                  cmdArgs.NetNS,
		K8SPodName:             cmdArgs.K8sPodName,
		K8SPodNamespace:        cmdArgs.K8sPodNameSpace,
		K8SPodInfraContainerId: cmdArgs.K8sInfraContainerID,
		IfName:                 cmdArgs.RawArgs.IfName,
	})

	if err != nil {
		log.Errorf("Create endpoint error: %s", err)
		err = fmt.Errorf("create endpoint error: %w", err)
		return nil, err
	}

	netNs, err := ns.GetNS(cmdArgs.NetNS)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns %q: %s", cmdArgs.NetNS, err)
	}
	defer netNs.Close()

	err, config := datapath.ParseSetupConfig(response, cmdArgs)

	if err != nil {
		log.Errorf("Parse config error: %w", err)
		return nil, fmt.Errorf("failed to parse setup configuration: %w", err)
	}
	fMutex, err := filemutex.New(types.DefaultCNILockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cni lock file, error: %s", err)
	}
	fMutex.Lock()
	defer fMutex.Unlock()

	switch config.DP {
	case types.VlanChaining:
		err = driver.NewVlanDriver(log).SetupNetwork(config)
	case types.MultiIP:
		err = driver.NewMultiIPDriver(log).SetupNetwork(config)
	default:
		return nil, fmt.Errorf("invalid datapath type")
	}

	if err != nil {
		log.Errorf("Setup network error: %w", err)
		return nil, fmt.Errorf("failed to setup network: %w", err)
	}

	result := &cniTypes100.Result{}
	result.Interfaces = append(result.Interfaces, &cniTypes100.Interface{
		Name:    types.DefaultContIfaceName,
		Sandbox: cmdArgs.NetNS,
	})

	result.IPs = append(result.IPs, &cniTypes100.IPConfig{
		Address:   *config.IPSet.IPv4,
		Gateway:   config.Gateway.IPv4.IP,
		Interface: cniTypes100.Int(0),
	})

	return result, nil
}

func cmdDel(args *skel.CmdArgs) error {

	delArgs, err := getCmdArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), types.DefaultCNITimeout)
	defer cancel()

	client, conn, err := cmdcommon.GetRaptorClient(ctx)
	if err != nil {
		return fmt.Errorf("error create grpc client, %w", err)
	}
	defer conn.Close()

	deleteEndpointResponse, err := client.DeleteEndpoint(ctx, &rpc.DeleteEndpointRequest{
		K8SPodName:             delArgs.K8sPodName,
		K8SPodNamespace:        delArgs.K8sPodNameSpace,
		K8SPodInfraContainerId: delArgs.K8sInfraContainerID,
	})

	if err != nil {
		owner := fmt.Sprintf("%s/%s", delArgs.K8sPodNameSpace, delArgs.K8sPodName)
		log.Errorf("Delete endpoint for pod %s error: %w.", owner, err)
		err = fmt.Errorf("cmdDel: error delete endpoint: %w", err)
		return err
	}

	fMutex, err := filemutex.New(types.DefaultCNILockPath)
	if err != nil {
		return fmt.Errorf("failed to open cni lock file, error: %s", err)
	}

	fMutex.Lock()
	defer fMutex.Unlock()

	config := datapath.ParseTeardownConfig(deleteEndpointResponse, args)

	switch config.DP {
	case types.VlanChaining:
		err = driver.NewVlanDriver(log).TeardownNetwork(config)
	case types.MultiIP:
		err = driver.NewMultiIPDriver(log).TeardownNetwork(config)
	default:
		return fmt.Errorf("invalid datapath type")
	}

	if args.ContainerID != "" && args.IfName != "" {
		// The container manager can delete the interface for us, but this is unreliable that
		// sometimes the container manager will fail to delete the interface for various reasons.
		// So we need to manually perform a cleanup here to avoid interface leaks.
		err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			iface, err := netlink.LinkByName(args.IfName)
			if err != nil {
				// The interface might be deleted by container manager, we can skip
				// deleting safely.
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					return nil
				}
				return fmt.Errorf("failed to get netlink %s: %v", args.IfName, err)
			}
			err = netlink.LinkDel(iface)
			if err != nil && err == ip.ErrLinkNotFound {
				return nil
			}
			return err
		})
		if err != nil {
			return fmt.Errorf("failed to delete interface %s in %s: %v", args.IfName, args.Netns, err)
		}
	}
	err = cleanIPRules()
	if err != nil {
		return err
	}

	return nil
}

func cmdCheck(_ *skel.CmdArgs) error {
	return nil
}

func cmdGC(_ *skel.CmdArgs) error {
	return nil
}

func cmdStatus(_ *skel.CmdArgs) error {
	return nil
}

func loadNetConf(bytes []byte) (*types.NetConf, error) {
	nc := &types.NetConf{}
	if err := json.Unmarshal(bytes, nc); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return nc, nil
}

func cleanIPRules() (err error) {
	var rules []netlink.Rule
	rules, err = netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var ipNets []*net.IPNet

	defer func() {
		for _, r := range rules {
			if r.Priority != types.ToContainerPriority && r.Priority != types.FromContainerPriority {
				continue
			}
			if r.IifName != "" || r.OifName != "" {
				continue
			}
			found := false

			for _, ipNet := range ipNets {
				if r.Dst != nil {
					if r.Dst.String() == ipNet.String() {
						found = true
						break
					}
				}
				if r.Src != nil {
					if r.Src.String() == ipNet.String() {
						found = true
						break
					}
				}
			}
			if !found {
				continue
			}
			_ = RuleDel(&r)
		}
	}()

	for _, r := range rules {
		if r.Priority != types.ToContainerPriority && r.Priority != types.FromContainerPriority {
			continue
		}
		name := r.IifName
		if name == "" {
			name = r.OifName
		}
		if name == "" {
			continue
		}
		_, err = netlink.LinkByName(name)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return err
			}
			err = RuleDel(&r)
			if err != nil {
				return err
			}
			var ipNet *net.IPNet
			if r.Dst != nil {
				ipNet = r.Dst
			}
			if r.Src != nil {
				ipNet = r.Src
			}
			if ipNet != nil {
				ipNets = append(ipNets, ipNet)
			}
		}
	}
	return nil
}

func RuleDel(rule *netlink.Rule) error {
	cmd := fmt.Sprintf("ip rule del %s", rule.String())
	err := netlink.RuleDel(rule)
	if err != nil {
		rule.IifName = ""
		rule.OifName = ""

		err = netlink.RuleDel(rule)
		if err != nil {
			return fmt.Errorf("error %s, %w", cmd, err)
		}
	}
	return nil
}
