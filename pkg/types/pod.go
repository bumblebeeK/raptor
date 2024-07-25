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

package types

import "context"

// PodAllocateContext contains the context information required for allocating a Pod.
type PodAllocateContext struct {
	context.Context
	Namespace string // Namespace
	Name      string // Pod name
	SandBoxId string // Sandbox ID
	Prefer    string // Preference
	Pool      string // Pool name
	SubnetId  string // Subnet ID
}

// PodReleaseContext contains the context information required for releasing a Pod.
type PodReleaseContext struct {
	context.Context
	Namespace  string // Namespace
	Name       string // Pod name
	SandBoxId  string // Sandbox ID
	Prefer     string // Prefer resource
	Pool       string // Pool name
	SubnetId   string // Subnet ID
	ResourceId string // Resource ID
}

// PodRecord represents information about an allocated Pod.
type PodRecord struct {
	Pool       string // Pool name
	ResourceId string // Resource ID
	SubnetId   string // Subnet ID
	Name       string // Pod name
	Namespace  string // Namespace
	Owner      string // Owner
	Trunk      bool
	SandBoxId  string
}
