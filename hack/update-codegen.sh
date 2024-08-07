#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}
GOPATH=${GOPATH}/src

source "${CODEGEN_PKG}/kube_codegen.sh"
kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    --input-pkg-root "github.com/easystack/raptor/pkg/k8s/apis" \
    --output-base "${GOPATH}" \

kube::codegen::gen_client \
    --with-watch \
    --output-base "${GOPATH}" \
    --output-pkg-root "github.com/easystack/raptor/pkg/k8s/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/custom-boilerplate.go.txt" \
    --input-pkg-root "github.com/easystack/raptor/pkg/k8s/apis" \
    --with-watch

