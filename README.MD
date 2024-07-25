# Raptor VPC CNI Network Plugin For Openstack

## Overview

Raptor VPC CNI is a Kubernetes CNI plugin designed for integration with OpenStack's Neutron and Nova components. It provides two types of data paths: auxiliary IP and trunk. The plugin enables efficient IP allocation and management for Pods within specified namespaces and nodes, and supports enhanced scheduling via device plugins and static IP assignment.

## Architecture
![architecture](/docs/img/architecture.png )

## Features

- **Auxiliary IP and Trunk Data Paths**: Supports both auxiliary IP and trunk-based network configurations.
- **Namespace-Based Scheduling**: Pods in specified namespaces (`selected_namespaces`) can utilize the defined `RaptorPodNetwork`.
- **Node-Based Scheduling**: IP allocation can be managed on specific nodes (`selected_nodes`).
- **Dynamic IP Allocation**: Selects the `RaptorPodNetwork` with the most available IPs for dynamic allocation.
- **Device Plugin Support**: Enhances scheduling capabilities.
- **Static IP Assignment**: Supports static IP assignment via Pod annotations (`raptor.io/static-ip-needed=true`).

## Installation

### Prerequisites

1. **OpenStack Environment**: Ensure you have a working OpenStack Neutron and Nova setup.
2. **Kubernetes Cluster**: Deploy a Kubernetes cluster using tools like `kubeadm`.
3. **Network Configuration**: Ensure network configurations are set up as per OpenStack requirements.

### Install Raptor VPC CNI

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/your-org/raptor-vpc-cni.git
    cd raptor-vpc-cni
    ```

2. **Deploy Raptor VPC CNI**:

    Replace `<your-config>` with your specific configuration details in the provided YAML file.

    ```bash
    kubectl apply -f raptor-vpc-cni.yml
    ```

## Configuration

![scheduler](/docs/img/scheduler.png )


### RaptorPodNetwork Custom Resource
The `RaptorPodNetwork` custom resource defines the network configurations for the Pods. Below is an example configuration:

```yaml
apiVersion: raptor.io/v1beta1
kind: RaptorPodNetwork
metadata:
  name: raptor-vpc-cni-v2-test-2-default-ipv4-subnet
spec:
  cidr: 10.29.22.0/24
  is-cluster-instance-subnet: false
  max-allocate: 10
  min-allocate: 2
  pre-allocate: 2
  selected-namespaces:
    - test-7
  selected-nodes:
    - node-4
    - node-5
  subnet-id: 2d3fa268-06ae-40fc-a88e-b9ec877eee54
  trunk-mode: false
  watermark: 2
status:
  active: true
  allocated-count: 6
  allocation-count: 251
  gateway-ip:
    IPv4: 10.29.22.1
```

### Static IP Assignment

To assign a static IP to a Pod, add the following annotation:

```yaml
metadata:
  annotations:
    raptor.io/static-ip-needed: "true"
```

## Usage

### Deploy a Pod Using Raptor VPC CNI

Deploy a sample Pod in a namespace that uses the `RaptorPodNetwork`.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sample-pod
  namespace: test-7
spec:
  containers:
    - name: sample-container
      image: nginx
```

### Monitor Raptor VPC CNI

Check the status of the Raptor VPC CNI daemonset:

```bash
kubectl get ds raptor -n kube-system
```

## Contributing

Contributions are welcome! Please submit issues or pull requests on our GitHub repository.

## License

Raptor VPC CNI is released under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.

