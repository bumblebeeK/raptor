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

package v1beta1

import (
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	RaptorStaticIPAPIVersion = "raptor.io/v1"
	RaptorStaticIPKind       = "RaptorStaticIP"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:JSONPath=".spec.ipv4",description="Raptor scheduler on which node",name="IPV4",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.node-name",description="Node for rsip",name="Node",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="Time duration since creation of raptorstaticip",name="Age",type=date
// +kubebuilder:resource:categories={rsip},singular="participator",path="raptorstaticips",shortName={rsip}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// RaptorStaticIP defines
type RaptorStaticIP struct {
	metaV1.TypeMeta   `json:",inline"`
	metaV1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec StaticIPSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status StaticIPStatus `json:"status"`
}

type StaticIPSpec struct {
	// +kubebuilder:validation:Required
	IPV4 string `json:"ipv4"`

	// +kubebuilder:validation:Optional
	IPV6 string `json:"ipv6,omitempty"`

	// +kubebuilder:validation:Required
	Pool string `json:"pool"`

	// +kubebuilder:validation:Optional
	NodeName string `json:"node-name"`

	// +kubebuilder:validation:Optional
	RecycleTime int `json:"recycle-time"`

	// +kubebuilder:validation:Optional
	NetworkId string `json:"network-id"`

	// +kubebuilder:validation:Optional
	ResourceId string `json:"resource-id"`
}

type StaticIPStatus struct {
	// +kubebuilder:validation:Optional
	UpdateTime metaV1.Time `json:"update-time"`

	// +kubebuilder:validation:Optional
	Phase string `json:"phase"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RaptorStaticIPList is a list of RaptorStaticIP objects.
type RaptorStaticIPList struct {
	metaV1.TypeMeta `json:",inline"`
	metaV1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of StaticIPs.
	Items []RaptorStaticIP `json:"items"`
}
