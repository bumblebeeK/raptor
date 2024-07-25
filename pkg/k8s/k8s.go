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

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/easystack/raptor/pkg/base"
	raptorV1Beta "github.com/easystack/raptor/pkg/k8s/apis/raptor.io/v1beta1"
	raptorClient "github.com/easystack/raptor/pkg/k8s/generated/clientset/versioned"
	"github.com/easystack/raptor/pkg/k8s/generated/informers/externalversions"
	raptorV1beta1 "github.com/easystack/raptor/pkg/k8s/generated/listers/raptor.io/v1beta1"
	"github.com/easystack/raptor/pkg/types"
	coreV1 "k8s.io/api/core/v1"
	k8sErr "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sType "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"reflect"
	"sync"
)

// log is used for logging purposes.
var log base.Log = base.NewLogWithField("sub_sys", "k8s_manager")

// Service defines the interface for managing Kubernetes-related operations.
type Service interface {
	ListLocalPods(ctx context.Context) ([]*coreV1.Pod, error)
	GetPod(ctx context.Context, namespace, name string) (*coreV1.Pod, error)
	PatchPodAnnotation(ctx context.Context, namespace, name string, anno map[string]string) error
	GetPendingPodCountByPool(ctx context.Context, name string, pool string) (int, error)
	PatchPodNetworkCondition(available, total, used int64, subnetId string, terminate bool) error
	PatchTrunkInfoToNode(ctx context.Context, info types.TrunkInfo) error
	GetIfPodStaticIPNeeded(ctx context.Context, namespace, name string) (bool, error)
	GetIfPodSpecificPoolNeeded(ctx context.Context, namespace, name string) (string, error)
	GetOrCreateStaticIPCR(ctx context.Context, namespace, name string) (*raptorV1Beta.RaptorStaticIP, error)
	ListRaptorPodNetworks(ctx context.Context) ([]*raptorV1Beta.RaptorPodNetwork, error)
	GetRaptorPodNetwork(ctx context.Context, name string) (*raptorV1Beta.RaptorPodNetwork, error)
	GetRaptorPodNetworkBySubnetId(ctx context.Context, subnetId string) (*raptorV1Beta.RaptorPodNetwork, error)
	CreateOrUpdateStaticIPCR(ctx context.Context, namespace string, cr *raptorV1Beta.RaptorStaticIP) error
	GetIfResourceReserved(ctx context.Context, podFullName string) (reserved bool, owner string)
}

// k8sManager implements the Service interface and contains necessary information and methods for managing Kubernetes resources.
type k8sManager struct {
	nodeName               string                               // Node name
	k8sClientSet           kubernetes.Interface                 // Kubernetes client
	raptorClientSet        raptorClient.Interface               // Raptor client
	raptorPodNetworkLister raptorV1beta1.RaptorPodNetworkLister // Raptor pod network lister
	raptorStaticIPLister   raptorV1beta1.RaptorStaticIPLister
	localPodLister         v1.PodLister
	reservedResource       reservedResourceMap
}

// NewK8sService creates a new instance of K8sService.
func NewK8sService(ctx context.Context, nodeName string, clientSet kubernetes.Interface, raptorClientSet raptorClient.Interface) (Service, error) {
	m := &k8sManager{
		k8sClientSet:     clientSet,
		nodeName:         nodeName,
		raptorClientSet:  raptorClientSet,
		reservedResource: newReservedResourceMap(),
	}

	m.initInformer(ctx)

	log.Infof("init informer success.")
	return m, nil
}

// PatchPodNetworkCondition updates the condition of Pod networks.
func (m *k8sManager) PatchPodNetworkCondition(available, total, used int64, subnetId string, terminate bool) error {
	c := raptorV1Beta.NodeConditions{
		Node:      m.nodeName,
		Total:     total,
		Available: available,
		Used:      used,
	}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		podNetworks, err := m.raptorPodNetworkLister.List(labels.Everything())
		if err != nil {
			return err
		}
		var newPodNetwork *raptorV1Beta.RaptorPodNetwork
		for i := range podNetworks {
			if podNetworks[i].Spec.SubnetId == subnetId {
				newPodNetwork = podNetworks[i]
				break
			}
		}

		if newPodNetwork == nil {
			return fmt.Errorf("podNetwork for subnet id %s not found", subnetId)
		}

		newPodNetwork = newPodNetwork.DeepCopy()

		found := false

		for index, condition := range newPodNetwork.Status.NodeConditions {
			if condition.Node == m.nodeName {
				// The pool has been recycled
				if terminate {
					newPodNetwork.Status.NodeConditions = append(newPodNetwork.Status.NodeConditions[:index],
						newPodNetwork.Status.NodeConditions[index+1:]...)
					break
				}

				newPodNetwork.Status.NodeConditions[index].LastTransitionTime = c.LastTransitionTime
				if reflect.DeepEqual(newPodNetwork.Status.NodeConditions[index], c) {
					return nil
				}
				c.LastTransitionTime = metaV1.Now()
				newPodNetwork.Status.NodeConditions[index] = c
				found = true
				break
			}
		}

		if !found {
			c.LastTransitionTime = metaV1.Now()
			newPodNetwork.Status.NodeConditions = append(newPodNetwork.Status.NodeConditions, c)
		}

		patch := map[string]interface{}{
			"status": map[string]interface{}{
				"node-conditions": newPodNetwork.Status.NodeConditions,
			},
		}
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			return err
		}

		_, err = m.raptorClientSet.RaptorV1beta1().RaptorPodNetworks().Patch(context.TODO(),
			newPodNetwork.Name,
			k8sType.MergePatchType,
			patchBytes,
			metaV1.PatchOptions{}, "status")
		return err
	})

	return err
}

// PatchTrunkInfoToNode updates trunk information on a node.
func (m *k8sManager) PatchTrunkInfoToNode(ctx context.Context, info types.TrunkInfo) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		annotations := map[string]string{types.TrunkNetworkAnnotation: fmt.Sprintf("trunkId:%s , trunkParentId: %s", info.TrunkId, info.TrunkParentId)}

		patchData := map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": annotations,
			},
		}

		patchBytes, err := json.Marshal(patchData)
		if err != nil {
			log.Errorf("Error marshaling patch data: %v", err)
			return err
		}

		_, err = m.k8sClientSet.CoreV1().Nodes().Patch(context.TODO(), m.nodeName, k8sType.StrategicMergePatchType, patchBytes, metaV1.PatchOptions{})
		return err
	})
}

// PatchPodAnnotation updates annotations on a Pod.
func (m *k8sManager) PatchPodAnnotation(ctx context.Context, namespace, name string, anno map[string]string) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {

		patchData := map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": anno,
			},
		}

		patchBytes, err := json.Marshal(patchData)
		if err != nil {
			log.Errorf("Error marshaling patch data: %v", err)
			return err
		}

		_, err = m.k8sClientSet.CoreV1().Pods(namespace).Patch(context.TODO(), name, k8sType.StrategicMergePatchType, patchBytes, metaV1.PatchOptions{})
		return err
	})

	return err
}

// GetPendingPodCountByPool gets the number of pending Pods in a specific pool.
func (m *k8sManager) GetPendingPodCountByPool(ctx context.Context, name string, pool string) (int, error) {
	pendingPods := 0

	podsList, err := m.localPodLister.Pods(coreV1.NamespaceAll).List(labels.Everything())
	if err != nil {
		return pendingPods, fmt.Errorf("failed to get pod list: %v", err)
	}

	for _, pod := range podsList {
		if pod.Status.Phase == coreV1.PodPending {
			if pod.Annotations != nil && pod.Annotations[types.PodNetworkAnnotation] == pool && !pod.Spec.HostNetwork {
				pendingPods++
			}
		}
	}
	return pendingPods, nil
}

// ListLocalPods lists Pods on the local node.
func (m *k8sManager) ListLocalPods(ctx context.Context) ([]*coreV1.Pod, error) {
	options := metaV1.ListOptions{
		FieldSelector:   fields.OneTermEqualSelector("spec.nodeName", m.nodeName).String(),
		ResourceVersion: "0",
	}

	list, err := m.k8sClientSet.CoreV1().Pods(coreV1.NamespaceAll).List(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list local pods, error is %s", err)
	}

	var podList []*coreV1.Pod

	for i := range list.Items {
		pod := list.Items[i]
		if !pod.Spec.HostNetwork {
			podList = append(podList, &pod)
		}
	}

	return podList, nil
}

// GetPod retrieves a specific Pod by namespace and name.
func (m *k8sManager) GetPod(ctx context.Context, namespace, name string) (*coreV1.Pod, error) {
	item, err := m.localPodLister.Pods(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s, error is %s", namespace, name, err)
	}

	return item, nil
}

// initInformer initializes the Pod informer.
func (m *k8sManager) initInformer(ctx context.Context) {

	factory := informers.NewSharedInformerFactoryWithOptions(m.k8sClientSet, 0, informers.WithTweakListOptions(func(options *metaV1.ListOptions) {
		options.Kind = "Pod"
		options.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + m.nodeName).String()
	}))

	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()

	defer runtime.HandleCrash()

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		log.Errorf("Timeout to wait pod informer synced")
		runtime.HandleError(fmt.Errorf("wait pod informer synced failed, timeout"))
		return
	}
	m.localPodLister = podInformer.Lister()

	raptorFactory := externalversions.NewSharedInformerFactory(m.raptorClientSet, 0)
	podNetworkInformer := raptorFactory.Raptor().V1beta1().RaptorPodNetworks()
	cacheInformer := podNetworkInformer.Informer()

	_, err := raptorFactory.Raptor().V1beta1().RaptorStaticIPs().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cr := obj.(*raptorV1Beta.RaptorStaticIP)
			m.reservedResource.add(cr.Spec.ResourceId, cr.Name+"/"+cr.Name)
		},
		DeleteFunc: func(obj interface{}) {
			cr := obj.(*raptorV1Beta.RaptorStaticIP)
			m.reservedResource.del(cr.Spec.ResourceId)
		},
	})

	if err != nil {
		log.Errorf("add static ip event handler error: %s", err)
		return
	}

	raptorFactory.Start(ctx.Done())

	raptorFactory.WaitForCacheSync(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), cacheInformer.HasSynced) {
		log.Errorf("Timeout to wait raptorPodNetwork informer synced")
		runtime.HandleError(fmt.Errorf("wait raptorPodNetwork informer synced failed, timeout"))
		return
	}

	m.raptorPodNetworkLister = podNetworkInformer.Lister()

}

// GetIfPodStaticIPNeeded checks if a specific Pod needs a static IP.
func (m *k8sManager) GetIfPodStaticIPNeeded(ctx context.Context, namespace, name string) (bool, error) {
	pod, err := m.GetPod(ctx, namespace, name)

	if err != nil {
		return false, err
	}

	if _, ok := pod.Annotations[types.StaticPodAnnotation]; ok {
		return true, nil
	}

	return false, nil
}

// GetOrCreateStaticIPCR gets or creates a static IP resource.
func (m *k8sManager) GetOrCreateStaticIPCR(ctx context.Context, namespace, name string) (*raptorV1Beta.RaptorStaticIP, error) {
	var resource *raptorV1Beta.RaptorStaticIP
	var err error
	resource, err = m.raptorClientSet.RaptorV1beta1().RaptorStaticIPs(namespace).Get(ctx, name, metaV1.GetOptions{ResourceVersion: "0"})

	if err != nil && !k8sErr.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get static ip resouces, error is: %s", err.Error())
	}

	if k8sErr.IsNotFound(err) {
		resource = &raptorV1Beta.RaptorStaticIP{
			TypeMeta: metaV1.TypeMeta{
				APIVersion: raptorV1Beta.RaptorStaticIPAPIVersion,
				Kind:       raptorV1Beta.RaptorStaticIPKind,
			},
			ObjectMeta: metaV1.ObjectMeta{
				Name:       name,
				Finalizers: []string{"raptor"},
			},
			Spec: raptorV1Beta.StaticIPSpec{
				NodeName: m.nodeName,
			},
			Status: raptorV1Beta.StaticIPStatus{},
		}
	} else {
		resource.Spec.NodeName = m.nodeName
	}

	return resource, nil
}

// GetIfPodSpecificPoolNeeded checks if a specific Pod needs a specific network pool.
func (m *k8sManager) GetIfPodSpecificPoolNeeded(ctx context.Context, namespace, name string) (string, error) {
	pod, err := m.GetPod(ctx, namespace, name)

	if err != nil {
		return "", err
	}

	if anno, ok := pod.Annotations[types.PodNetworkAnnotation]; ok {
		return anno, nil
	}

	return "", nil
}

// ListRaptorPodNetworks lists all Raptor Pod networks.
func (m *k8sManager) ListRaptorPodNetworks(ctx context.Context) ([]*raptorV1Beta.RaptorPodNetwork, error) {
	return m.raptorPodNetworkLister.List(labels.Everything())
}

// GetRaptorPodNetwork gets a specific Raptor Pod network by name.
func (m *k8sManager) GetRaptorPodNetwork(ctx context.Context, name string) (*raptorV1Beta.RaptorPodNetwork, error) {
	return m.raptorPodNetworkLister.Get(name)
}

// GetRaptorPodNetworkBySubnetId gets a Raptor Pod network by subnet ID.
func (m *k8sManager) GetRaptorPodNetworkBySubnetId(ctx context.Context, subnetId string) (*raptorV1Beta.RaptorPodNetwork, error) {
	networks, err := m.ListRaptorPodNetworks(ctx)
	if err != nil {
		return nil, err
	}

	for _, network := range networks {
		if network.Spec.SubnetId == subnetId {
			return network, nil
		}
	}
	var resource raptorV1Beta.RaptorPodNetwork

	return nil, k8sErr.NewNotFound(schema.GroupResource{
		Group:    resource.GroupVersionKind().Group,
		Resource: resource.GroupVersionKind().Kind,
	}, subnetId)
}

func (m *k8sManager) CreateOrUpdateStaticIPCR(ctx context.Context, namespace string, cr *raptorV1Beta.RaptorStaticIP) error {
	var err error
	log.Infof("Create or update rsip %s", cr.Name)
	if cr.CreationTimestamp.IsZero() {
		_, err = m.raptorClientSet.RaptorV1beta1().RaptorStaticIPs(namespace).Create(ctx, cr, metaV1.CreateOptions{})
		return err
	}
	_, err = m.raptorClientSet.RaptorV1beta1().RaptorStaticIPs(namespace).Update(ctx, cr, metaV1.UpdateOptions{})
	return err
}

func (m *k8sManager) GetIfResourceReserved(ctx context.Context, podFullName string) (found bool, value string) {
	return m.reservedResource.get(podFullName)
}

type reservedResourceMap struct {
	data map[string]string
	sync.RWMutex
}

func newReservedResourceMap() reservedResourceMap {
	return reservedResourceMap{
		data: map[string]string{},
	}
}

func (r *reservedResourceMap) add(key, value string) {
	r.RWMutex.Lock()
	defer r.RWMutex.Unlock()
	r.data[key] = value
}

func (r *reservedResourceMap) del(key string) {
	r.RWMutex.Lock()
	defer r.RWMutex.Unlock()
	delete(r.data, key)
}

func (r *reservedResourceMap) get(key string) (found bool, value string) {
	r.RWMutex.RLock()
	defer r.RWMutex.RUnlock()
	value, found = r.data[key]
	return
}
