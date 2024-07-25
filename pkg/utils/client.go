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

package utils

import (
	"fmt"
	"os"
	"sync"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	raptorClient "github.com/easystack/raptor/pkg/k8s/generated/clientset/versioned"
)

var (
	// Kubernetes clientset and custom resource clientset
	client *kubernetes.Clientset
	crd    *raptorClient.Clientset

	// Synchronization primitives to ensure the initialization functions are called only once
	clientOnce sync.Once
	crdOnce    sync.Once

	// Kubernetes REST configuration and its initialization synchronization primitive
	config     *rest.Config
	configOnce sync.Once
)

// GetConfig initializes and returns the in-cluster Kubernetes REST configuration.
// It ensures that the configuration is initialized only once using sync.Once.
func GetConfig() (*rest.Config, error) {
	var err error
	configOnce.Do(func() {
		// Get the in-cluster configuration
		config, err = rest.InClusterConfig()
		if err != nil {
			err = fmt.Errorf("failed to generate kubernetes client config: %v", err)
			return
		}
	})
	return config, err
}

// GetConfigFromKube initializes and returns the Kubernetes REST configuration
// from a local kubeconfig file. It ensures that the configuration is initialized only once using sync.Once.
func GetConfigFromKube() (*rest.Config, error) {
	var err error
	configOnce.Do(func() {
		kubeConfigPath := "/root/.kube/config"

		// Read the kubeconfig file
		kubeConfig, err := os.ReadFile(kubeConfigPath)
		if err != nil {
			return
		}

		// Generate the REST configuration from the kubeconfig content
		config, err = clientcmd.RESTConfigFromKubeConfig(kubeConfig)
		if err != nil {
			return
		}
	})
	return config, err
}

// GetRaptorClient initializes and returns the custom resource clientset for Raptor.
// It ensures that the clientset is initialized only once using sync.Once.
func GetRaptorClient() (*raptorClient.Clientset, error) {
	var err error
	crdOnce.Do(func() {
		var cfg *rest.Config
		cfg, err = GetConfigFromKube()
		if err != nil {
			return
		}
		crd, err = raptorClient.NewForConfig(cfg)
		if err != nil {
			err = fmt.Errorf("failed to generate raptor crd client: %v", err)
			return
		}
	})
	return crd, err
}

// Path to the kubeconfig file used by the node
const nodeKubeConfigPath = "/etc/kubernetes/kubelet.kubeconfig"

// GetNodeClient initializes and returns the Kubernetes clientset using the node's kubeconfig file.
func GetNodeClient() (*kubernetes.Clientset, error) {
	// Build the configuration from the node's kubeconfig file
	cfg, err := clientcmd.BuildConfigFromFlags("", nodeKubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kube config: %v", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// GetK8sClient initializes and returns the Kubernetes clientset.
// It ensures that the clientset is initialized only once using sync.Once.
func GetK8sClient() (*kubernetes.Clientset, error) {
	var err error
	clientOnce.Do(func() {
		var cfg *rest.Config
		cfg, err = GetConfigFromKube()
		if err != nil {
			return
		}
		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			err = fmt.Errorf("failed to generate kubernetes client: %v", err)
			return
		}
	})
	return client, err
}
