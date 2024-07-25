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
// Code generated by client-gen. DO NOT EDIT.

package v1beta1

import (
	"context"
	"time"

	v1beta1 "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	scheme "github.com/easystack/raptor/pkg/k8s/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// RaptorPodNetworksGetter has a method to return a RaptorPodNetworkInterface.
// A group's client should implement this interface.
type RaptorPodNetworksGetter interface {
	RaptorPodNetworks() RaptorPodNetworkInterface
}

// RaptorPodNetworkInterface has methods to work with RaptorPodNetwork resources.
type RaptorPodNetworkInterface interface {
	Create(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.CreateOptions) (*v1beta1.RaptorPodNetwork, error)
	Update(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.UpdateOptions) (*v1beta1.RaptorPodNetwork, error)
	UpdateStatus(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.UpdateOptions) (*v1beta1.RaptorPodNetwork, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1beta1.RaptorPodNetwork, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1beta1.RaptorPodNetworkList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.RaptorPodNetwork, err error)
	RaptorPodNetworkExpansion
}

// raptorPodNetworks implements RaptorPodNetworkInterface
type raptorPodNetworks struct {
	client rest.Interface
}

// newRaptorPodNetworks returns a RaptorPodNetworks
func newRaptorPodNetworks(c *RaptorV1beta1Client) *raptorPodNetworks {
	return &raptorPodNetworks{
		client: c.RESTClient(),
	}
}

// Get takes name of the raptorPodNetwork, and returns the corresponding raptorPodNetwork object, and an error if there is any.
func (c *raptorPodNetworks) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.RaptorPodNetwork, err error) {
	result = &v1beta1.RaptorPodNetwork{}
	err = c.client.Get().
		Resource("raptorpodnetworks").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of RaptorPodNetworks that match those selectors.
func (c *raptorPodNetworks) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.RaptorPodNetworkList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1beta1.RaptorPodNetworkList{}
	err = c.client.Get().
		Resource("raptorpodnetworks").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested raptorPodNetworks.
func (c *raptorPodNetworks) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("raptorpodnetworks").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a raptorPodNetwork and creates it.  Returns the server's representation of the raptorPodNetwork, and an error, if there is any.
func (c *raptorPodNetworks) Create(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.CreateOptions) (result *v1beta1.RaptorPodNetwork, err error) {
	result = &v1beta1.RaptorPodNetwork{}
	err = c.client.Post().
		Resource("raptorpodnetworks").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(raptorPodNetwork).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a raptorPodNetwork and updates it. Returns the server's representation of the raptorPodNetwork, and an error, if there is any.
func (c *raptorPodNetworks) Update(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.UpdateOptions) (result *v1beta1.RaptorPodNetwork, err error) {
	result = &v1beta1.RaptorPodNetwork{}
	err = c.client.Put().
		Resource("raptorpodnetworks").
		Name(raptorPodNetwork.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(raptorPodNetwork).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *raptorPodNetworks) UpdateStatus(ctx context.Context, raptorPodNetwork *v1beta1.RaptorPodNetwork, opts v1.UpdateOptions) (result *v1beta1.RaptorPodNetwork, err error) {
	result = &v1beta1.RaptorPodNetwork{}
	err = c.client.Put().
		Resource("raptorpodnetworks").
		Name(raptorPodNetwork.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(raptorPodNetwork).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the raptorPodNetwork and deletes it. Returns an error if one occurs.
func (c *raptorPodNetworks) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("raptorpodnetworks").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *raptorPodNetworks) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("raptorpodnetworks").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched raptorPodNetwork.
func (c *raptorPodNetworks) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.RaptorPodNetwork, err error) {
	result = &v1beta1.RaptorPodNetwork{}
	err = c.client.Patch(pt).
		Resource("raptorpodnetworks").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}