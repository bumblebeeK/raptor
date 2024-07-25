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

package fake

import (
	"context"

	v1beta1 "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeRaptorStaticIPs implements RaptorStaticIPInterface
type FakeRaptorStaticIPs struct {
	Fake *FakeRaptorV1beta1
	ns   string
}

var raptorstaticipsResource = v1beta1.SchemeGroupVersion.WithResource("raptorstaticips")

var raptorstaticipsKind = v1beta1.SchemeGroupVersion.WithKind("RaptorStaticIP")

// Get takes name of the raptorStaticIP, and returns the corresponding raptorStaticIP object, and an error if there is any.
func (c *FakeRaptorStaticIPs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.RaptorStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(raptorstaticipsResource, c.ns, name), &v1beta1.RaptorStaticIP{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.RaptorStaticIP), err
}

// List takes label and field selectors, and returns the list of RaptorStaticIPs that match those selectors.
func (c *FakeRaptorStaticIPs) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.RaptorStaticIPList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(raptorstaticipsResource, raptorstaticipsKind, c.ns, opts), &v1beta1.RaptorStaticIPList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.RaptorStaticIPList{ListMeta: obj.(*v1beta1.RaptorStaticIPList).ListMeta}
	for _, item := range obj.(*v1beta1.RaptorStaticIPList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested raptorStaticIPs.
func (c *FakeRaptorStaticIPs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(raptorstaticipsResource, c.ns, opts))

}

// Create takes the representation of a raptorStaticIP and creates it.  Returns the server's representation of the raptorStaticIP, and an error, if there is any.
func (c *FakeRaptorStaticIPs) Create(ctx context.Context, raptorStaticIP *v1beta1.RaptorStaticIP, opts v1.CreateOptions) (result *v1beta1.RaptorStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(raptorstaticipsResource, c.ns, raptorStaticIP), &v1beta1.RaptorStaticIP{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.RaptorStaticIP), err
}

// Update takes the representation of a raptorStaticIP and updates it. Returns the server's representation of the raptorStaticIP, and an error, if there is any.
func (c *FakeRaptorStaticIPs) Update(ctx context.Context, raptorStaticIP *v1beta1.RaptorStaticIP, opts v1.UpdateOptions) (result *v1beta1.RaptorStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(raptorstaticipsResource, c.ns, raptorStaticIP), &v1beta1.RaptorStaticIP{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.RaptorStaticIP), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeRaptorStaticIPs) UpdateStatus(ctx context.Context, raptorStaticIP *v1beta1.RaptorStaticIP, opts v1.UpdateOptions) (*v1beta1.RaptorStaticIP, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(raptorstaticipsResource, "status", c.ns, raptorStaticIP), &v1beta1.RaptorStaticIP{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.RaptorStaticIP), err
}

// Delete takes name of the raptorStaticIP and deletes it. Returns an error if one occurs.
func (c *FakeRaptorStaticIPs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(raptorstaticipsResource, c.ns, name, opts), &v1beta1.RaptorStaticIP{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeRaptorStaticIPs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(raptorstaticipsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.RaptorStaticIPList{})
	return err
}

// Patch applies the patch and returns the patched raptorStaticIP.
func (c *FakeRaptorStaticIPs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.RaptorStaticIP, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(raptorstaticipsResource, c.ns, name, pt, data, subresources...), &v1beta1.RaptorStaticIP{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1beta1.RaptorStaticIP), err
}