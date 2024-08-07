// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v3.12.4
// source: rpc/cni.proto

package rpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	RaptorBackend_CreateEndpoint_FullMethodName   = "/rpc.RaptorBackend/CreateEndpoint"
	RaptorBackend_DeleteEndpoint_FullMethodName   = "/rpc.RaptorBackend/DeleteEndpoint"
	RaptorBackend_BorrowIP_FullMethodName         = "/rpc.RaptorBackend/BorrowIP"
	RaptorBackend_ListNetworkCards_FullMethodName = "/rpc.RaptorBackend/ListNetworkCards"
	RaptorBackend_ListVpcIPs_FullMethodName       = "/rpc.RaptorBackend/ListVpcIPs"
	RaptorBackend_ListPodRecords_FullMethodName   = "/rpc.RaptorBackend/ListPodRecords"
)

// RaptorBackendClient is the client API for RaptorBackend service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RaptorBackendClient interface {
	CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error)
	DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error)
	BorrowIP(ctx context.Context, in *BorrowIPRequest, opts ...grpc.CallOption) (*BorrowIPResponse, error)
	ListNetworkCards(ctx context.Context, in *ListNetworkCardsRequest, opts ...grpc.CallOption) (*ListNetworkCardsResponse, error)
	ListVpcIPs(ctx context.Context, in *ListVpcIPsRequest, opts ...grpc.CallOption) (*ListVpcIPsResponse, error)
	ListPodRecords(ctx context.Context, in *ListPodRecordsRequest, opts ...grpc.CallOption) (*ListPodRecordsResponse, error)
}

type raptorBackendClient struct {
	cc grpc.ClientConnInterface
}

func NewRaptorBackendClient(cc grpc.ClientConnInterface) RaptorBackendClient {
	return &raptorBackendClient{cc}
}

func (c *raptorBackendClient) CreateEndpoint(ctx context.Context, in *CreateEndpointRequest, opts ...grpc.CallOption) (*CreateEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateEndpointResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_CreateEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *raptorBackendClient) DeleteEndpoint(ctx context.Context, in *DeleteEndpointRequest, opts ...grpc.CallOption) (*DeleteEndpointResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteEndpointResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_DeleteEndpoint_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *raptorBackendClient) BorrowIP(ctx context.Context, in *BorrowIPRequest, opts ...grpc.CallOption) (*BorrowIPResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BorrowIPResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_BorrowIP_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *raptorBackendClient) ListNetworkCards(ctx context.Context, in *ListNetworkCardsRequest, opts ...grpc.CallOption) (*ListNetworkCardsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListNetworkCardsResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_ListNetworkCards_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *raptorBackendClient) ListVpcIPs(ctx context.Context, in *ListVpcIPsRequest, opts ...grpc.CallOption) (*ListVpcIPsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListVpcIPsResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_ListVpcIPs_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *raptorBackendClient) ListPodRecords(ctx context.Context, in *ListPodRecordsRequest, opts ...grpc.CallOption) (*ListPodRecordsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListPodRecordsResponse)
	err := c.cc.Invoke(ctx, RaptorBackend_ListPodRecords_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RaptorBackendServer is the server API for RaptorBackend service.
// All implementations must embed UnimplementedRaptorBackendServer
// for forward compatibility
type RaptorBackendServer interface {
	CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error)
	DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error)
	BorrowIP(context.Context, *BorrowIPRequest) (*BorrowIPResponse, error)
	ListNetworkCards(context.Context, *ListNetworkCardsRequest) (*ListNetworkCardsResponse, error)
	ListVpcIPs(context.Context, *ListVpcIPsRequest) (*ListVpcIPsResponse, error)
	ListPodRecords(context.Context, *ListPodRecordsRequest) (*ListPodRecordsResponse, error)
	mustEmbedUnimplementedRaptorBackendServer()
}

// UnimplementedRaptorBackendServer must be embedded to have forward compatible implementations.
type UnimplementedRaptorBackendServer struct {
}

func (UnimplementedRaptorBackendServer) CreateEndpoint(context.Context, *CreateEndpointRequest) (*CreateEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEndpoint not implemented")
}
func (UnimplementedRaptorBackendServer) DeleteEndpoint(context.Context, *DeleteEndpointRequest) (*DeleteEndpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteEndpoint not implemented")
}
func (UnimplementedRaptorBackendServer) BorrowIP(context.Context, *BorrowIPRequest) (*BorrowIPResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BorrowIP not implemented")
}
func (UnimplementedRaptorBackendServer) ListNetworkCards(context.Context, *ListNetworkCardsRequest) (*ListNetworkCardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListNetworkCards not implemented")
}
func (UnimplementedRaptorBackendServer) ListVpcIPs(context.Context, *ListVpcIPsRequest) (*ListVpcIPsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListVpcIPs not implemented")
}
func (UnimplementedRaptorBackendServer) ListPodRecords(context.Context, *ListPodRecordsRequest) (*ListPodRecordsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPodRecords not implemented")
}
func (UnimplementedRaptorBackendServer) mustEmbedUnimplementedRaptorBackendServer() {}

// UnsafeRaptorBackendServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RaptorBackendServer will
// result in compilation errors.
type UnsafeRaptorBackendServer interface {
	mustEmbedUnimplementedRaptorBackendServer()
}

func RegisterRaptorBackendServer(s grpc.ServiceRegistrar, srv RaptorBackendServer) {
	s.RegisterService(&RaptorBackend_ServiceDesc, srv)
}

func _RaptorBackend_CreateEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).CreateEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_CreateEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).CreateEndpoint(ctx, req.(*CreateEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RaptorBackend_DeleteEndpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteEndpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).DeleteEndpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_DeleteEndpoint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).DeleteEndpoint(ctx, req.(*DeleteEndpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RaptorBackend_BorrowIP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BorrowIPRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).BorrowIP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_BorrowIP_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).BorrowIP(ctx, req.(*BorrowIPRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RaptorBackend_ListNetworkCards_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListNetworkCardsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).ListNetworkCards(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_ListNetworkCards_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).ListNetworkCards(ctx, req.(*ListNetworkCardsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RaptorBackend_ListVpcIPs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListVpcIPsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).ListVpcIPs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_ListVpcIPs_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).ListVpcIPs(ctx, req.(*ListVpcIPsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RaptorBackend_ListPodRecords_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPodRecordsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RaptorBackendServer).ListPodRecords(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RaptorBackend_ListPodRecords_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RaptorBackendServer).ListPodRecords(ctx, req.(*ListPodRecordsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RaptorBackend_ServiceDesc is the grpc.ServiceDesc for RaptorBackend service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RaptorBackend_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "rpc.RaptorBackend",
	HandlerType: (*RaptorBackendServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateEndpoint",
			Handler:    _RaptorBackend_CreateEndpoint_Handler,
		},
		{
			MethodName: "DeleteEndpoint",
			Handler:    _RaptorBackend_DeleteEndpoint_Handler,
		},
		{
			MethodName: "BorrowIP",
			Handler:    _RaptorBackend_BorrowIP_Handler,
		},
		{
			MethodName: "ListNetworkCards",
			Handler:    _RaptorBackend_ListNetworkCards_Handler,
		},
		{
			MethodName: "ListVpcIPs",
			Handler:    _RaptorBackend_ListVpcIPs_Handler,
		},
		{
			MethodName: "ListPodRecords",
			Handler:    _RaptorBackend_ListPodRecords_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rpc/cni.proto",
}
