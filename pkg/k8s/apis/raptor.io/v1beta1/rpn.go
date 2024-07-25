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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={rpn},singular="raptorpodnetwork",path="raptorpodnetworks",scope="Cluster",shortName={rpn}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// RaptorPodNetwork defines an IP pool that can be used for pooled IPAM (i.e. the multi-pool IPAM
// mode).
type RaptorPodNetwork struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec PodNetworkSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status PodNetworkStatus `json:"status"`
}

type PodNetworkSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule=(self == oldSelf)
	SubnetId string `json:"subnet-id"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule=(self == oldSelf)
	CIDR string `json:"cidr"`

	// +kubebuilder:validation:Optional
	PreAllocate int `json:"pre-allocate"`

	// +kubebuilder:validation:Optional
	MinAllocate int `json:"min-allocate"`

	// +kubebuilder:validation:Optional
	MaxAllocate int `json:"max-allocate"`

	// +kubebuilder:validation:Optional
	Watermark int `json:"watermark"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule=(self == oldSelf)
	IsClusterInstanceSubnet bool `json:"is-cluster-instance-subnet"`

	// +kubebuilder:validation:Optional
	SelectedNodes []string `json:"selected-nodes"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule=(self == oldSelf)
	TrunkMode bool `json:"trunk-mode"`

	// +kubebuilder:validation:Optional
	SelectedNodeLabel []string `json:"selected-node-label"`

	// +kubebuilder:validation:Optional
	SelectedNameSpace []string `json:"selected-namespaces"`
}

type GatewayIP struct {
	IPv4 string `json:"IPv4"`
	IPv6 string `json:"IPv6"`
}

// PodNetworkStatus describe the status of the nodes which uses the pool
type PodNetworkStatus struct {
	// +kubebuilder:validation:Optional
	Active bool `json:"active"`

	// +kubebuilder:validation:Optional
	AllocationCount int64 `json:"allocation-count"`

	// +kubebuilder:validation:Optional
	AllocatedCount int64 `json:"allocated-count"`

	// +kubebuilder:validation:Optional
	GatewayIP GatewayIP `json:"gateway-ip"`

	// +kubebuilder:validation:Optional
	NetworkId string `json:"network-id"`

	// Current service state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=node
	NodeConditions []NodeConditions `json:"node-conditions,omitempty" patchStrategy:"merge" patchMergeKey:"node"`
}

type NodeConditions struct {
	// +required
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])$`
	// +kubebuilder:validation:MaxLength=316
	Node string `json:"node" protobuf:"bytes,1,opt,name=node"`

	// +optional
	// +kubebuilder:validation:Minimum=0
	Total int64 `json:"total" protobuf:"varint,3,opt,name=total"`

	// +required
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	LastTransitionTime metav1.Time `json:"lastTransitionTime" protobuf:"bytes,4,opt,name=lastTransitionTime"`

	// +optional
	// +kubebuilder:validation:Minimum=0
	Available int64 `json:"available" protobuf:"varint,5,opt,name=available"`

	// +optional
	// +kubebuilder:validation:Minimum=0
	Used int64 `json:"used" protobuf:"varint,6,opt,name=available"`

	// +optional
	NetworkCards []string `json:"networkCards" protobuf:"bytes,7,opt,name=networkcards"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// RaptorPodNetworkList is a list of RaptorPodNetwork objects.
type RaptorPodNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of RaptorPodNetworks.
	Items []RaptorPodNetwork `json:"items"`
}
