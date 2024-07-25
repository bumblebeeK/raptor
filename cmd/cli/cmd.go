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
	"github.com/easystack/raptor/pkg/storage/bolt"
	"github.com/easystack/raptor/pkg/types"
	"github.com/spf13/cobra"
	"os"
	"reflect"
	"text/tabwriter"
)

var resource, name, subnetId string

var engine *bolt.BoltEngine

var cliCmd = &cobra.Command{
	Use:   "raptor-cli",
	Short: "raptor-cli is a command line tool for vpc resources.",
	Long:  `raptor-cli is a command line tool for vpc resources`,

	Run: func(cmd *cobra.Command, args []string) {
		var err error

		if resource == "" {
			cmd.Help()
			os.Exit(1)
		}

		// This function will be executed when no subcommands are provided
		// Check if the file exists
		if _, err := os.Stat(types.BoltDBPath); os.IsNotExist(err) {
			fmt.Println("database file does not exist.")
			return
		}

		engine, err = bolt.NewEngine(types.BoltDBPath)

		defer engine.Close()
		if err != nil {
			fmt.Printf("Failed to open db file, error: %s.\n", err)
			return
		}
		var data any
		switch resource {
		case "networkCard":
			data, err = getNetworkCardInfo(name)
			if err != nil {
				fmt.Println("Failed to get network card info")
				return
			}
		case "podRecord":
			data, err = getPodRecordInfo(name)
			if err != nil {
				fmt.Println("Failed to get network card info")
				return
			}
		case "vpcIP":
			data, err = getVPCIPInfo(name, subnetId)
			fmt.Println("not support")
		}
		printStructTable(data)
	},
}

func Execute() {
	cliCmd.Flags().StringVarP(&resource, "resource", "r", "", "resource kind to get")
	cliCmd.Flags().StringVarP(&name, "name", "n", "", "resource to get")
	cliCmd.Flags().StringVarP(&name, "subnet-id", "s", "", "resource to get in subnet")

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
	numFields := elemType.NumField()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight|tabwriter.Debug)
	defer w.Flush()

	// 打印表头
	for i := 0; i < numFields; i++ {
		field := elemType.Field(i)
		fmt.Fprintf(w, "%s\t", field.Name)
	}
	fmt.Fprintln(w) // 新行

	// 打印分隔线
	for i := 0; i < numFields; i++ {
		fmt.Fprintf(w, "----\t")
	}
	fmt.Fprintln(w) // 新行

	// 打印数据行
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		for j := 0; j < numFields; j++ {
			field := elem.Field(j)
			fmt.Fprintf(w, "%v\t", field.Interface())
		}
		fmt.Fprintln(w) // 新行
	}
}
