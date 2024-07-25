//go:build tools

package tools

import (
	_ "golang.org/x/tools/cmd/goimports"
	_ "k8s.io/code-generator"
	_ "k8s.io/code-generator/cmd/client-gen"
	_ "k8s.io/code-generator/cmd/go-to-protobuf"
	_ "k8s.io/code-generator/cmd/go-to-protobuf/protoc-gen-gogo"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
