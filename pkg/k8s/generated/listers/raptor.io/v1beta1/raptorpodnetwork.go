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
// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// RaptorPodNetworkLister helps list RaptorPodNetworks.
// All objects returned here must be treated as read-only.
type RaptorPodNetworkLister interface {
	// List lists all RaptorPodNetworks in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.RaptorPodNetwork, err error)
	// Get retrieves the RaptorPodNetwork from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.RaptorPodNetwork, error)
	RaptorPodNetworkListerExpansion
}

// raptorPodNetworkLister implements the RaptorPodNetworkLister interface.
type raptorPodNetworkLister struct {
	indexer cache.Indexer
}

// NewRaptorPodNetworkLister returns a new RaptorPodNetworkLister.
func NewRaptorPodNetworkLister(indexer cache.Indexer) RaptorPodNetworkLister {
	return &raptorPodNetworkLister{indexer: indexer}
}

// List lists all RaptorPodNetworks in the indexer.
func (s *raptorPodNetworkLister) List(selector labels.Selector) (ret []*v1beta1.RaptorPodNetwork, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.RaptorPodNetwork))
	})
	return ret, err
}

// Get retrieves the RaptorPodNetwork from the index for a given name.
func (s *raptorPodNetworkLister) Get(name string) (*v1beta1.RaptorPodNetwork, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("raptorpodnetwork"), name)
	}
	return obj.(*v1beta1.RaptorPodNetwork), nil
}
