#	Copyright EasyStack. All Rights Reserved.
#
#	Licensed under the Apache License, Version 2.0 (the "License"). You may
#	not use this file except in compliance with the License. A copy of the
#	License is located at
#
#	https://www.apache.org/licenses/LICENSE-2.0
#
#	or in the "license" file accompanying this file. This file is distributed
#	on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
#	express or implied. See the License for the specific language governing
#	permissions and limitations under the License.

CRDS_RAPTOR_V1BETA1 := raptorstaticips \
					   raptorpodnetworks

CRD_OPTIONS ?= "crd:crdVersions=v1"
CRD_PATHS := "$(PWD)/pkg/k8s/apis/raptor.io/v1beta1;"
GO ?= go

generate-k8s-api:
	bash ./hack/update-codegen.sh

manifests:
	$(eval TMPDIR := ./tmp)
	$(GO) run sigs.k8s.io/controller-tools/cmd/controller-gen  \
			$(CRD_OPTIONS) paths=$(CRD_PATHS) output:crd:artifacts:config="$(TMPDIR)"
	cp $(TMPDIR)/* ./deploy
	rm -rf $(TMPDIR)



