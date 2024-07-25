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
	"fmt"
	"os"
	"reflect"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var resource, subnetId, pool, namespace string

const (
	NetworkCardType = "networkCard"
	PodRecord       = "podRecord"
	VpcIP           = "vpcIP"
)

var cliCmd = &cobra.Command{
	Use:   "raptor-cli -r <resource>",
	Short: "raptor-cli is a command line tool for vpc resources.",
	Long:  `raptor-cli is a command line tool for vpc resources`,

	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if resource == "" {
			cmd.Help()
			os.Exit(1)
		}
		var data any
		switch resource {
		case NetworkCardType:
			data, err = getNetworkCardInfo()
			if err != nil {
				fmt.Println("Failed to get network card info")
				return err
			}
		case PodRecord:
			data, err = getPodRecordInfo(subnetId, pool, namespace)
			if err != nil {
				fmt.Println("Failed to get network card info")
				return err
			}
		case VpcIP:
			data, err = getVPCIPInfo(subnetId, pool)
			if err != nil {
				fmt.Println("Failed to get network card info")
				return err
			}
		default:
			errLog := fmt.Sprintf("resource kind [%s] not in [%s | %s | %s]", resource, NetworkCardType, PodRecord, VpcIP)
			fmt.Println("Error: ", errLog)
			return err
		}
		printStructTable(data)
		return err
	},
}

func Execute() {
	resourceUsage := fmt.Sprintf("resource kind to get for: [%s | %s | %s]", NetworkCardType, PodRecord, VpcIP)
	cliCmd.Flags().StringVarP(&resource, "resource", "r", "", resourceUsage)

	subnetIdUsage := fmt.Sprintf("get the resource kind: [%s | %s] by specified subnetId", PodRecord, VpcIP)
	cliCmd.Flags().StringVarP(&subnetId, "subnet-id", "s", "", subnetIdUsage)

	poolUsage := fmt.Sprintf("get the resource kind: [%s | %s] by specified pool", PodRecord, VpcIP)
	cliCmd.Flags().StringVarP(&pool, "pool", "p", "", poolUsage)

	namespaceUsage := fmt.Sprintf("get the resource kind: [%s] by specified namespace", PodRecord)
	cliCmd.Flags().StringVarP(&namespace, "namespace", "n", "", namespaceUsage)

	if err := cliCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func printStructTable(data any) {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Slice {
		fmt.Println("Expected a slice of structs")
		return
	}
	if v.Len() == 0 {
		fmt.Println("No data to print")
		return
	}

	elemType := v.Index(0).Type()

	numFields := elemType.Elem().NumField()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
	defer w.Flush()

	fmt.Fprintln(w) // 新行

	// 打印表头
	for i := 3; i < numFields; i++ {
		field := elemType.Elem().Field(i)
		fmt.Fprintf(w, "%s\t", field.Name)
	}
	fmt.Fprintln(w) // 新行

	// 打印分隔线
	for i := 3; i < numFields; i++ {
		fmt.Fprintf(w, "----------\t")
	}
	fmt.Fprintln(w) // 新行

	// 打印数据行
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		for j := 3; j < numFields; j++ {
			if elem.Kind() == reflect.Ptr {
				elem = elem.Elem()
			}
			field := elem.Field(j)
			if field.CanInterface() {
				fmt.Fprintf(w, "%v\t", field.Interface())
			} else {
				fmt.Fprintf(w, "%v\t", "")
			}
		}
		fmt.Fprintln(w) // 新行
	}
	fmt.Fprintln(w) // 新行
}
