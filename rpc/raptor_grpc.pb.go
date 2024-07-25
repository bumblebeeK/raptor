// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             v3.12.4
// source: rpc/raptor.proto

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
	CoordinatorBackend_AcquireInstanceInfo_FullMethodName = "/rpc.CoordinatorBackend/AcquireInstanceInfo"
	CoordinatorBackend_AllocateIPResource_FullMethodName  = "/rpc.CoordinatorBackend/AllocateIPResource"
	CoordinatorBackend_ReleaseIPResource_FullMethodName   = "/rpc.CoordinatorBackend/ReleaseIPResource"
	CoordinatorBackend_AllocateNetworkCard_FullMethodName = "/rpc.CoordinatorBackend/AllocateNetworkCard"
	CoordinatorBackend_ReleaseNetworkCard_FullMethodName  = "/rpc.CoordinatorBackend/ReleaseNetworkCard"
	CoordinatorBackend_TransferIPResource_FullMethodName  = "/rpc.CoordinatorBackend/TransferIPResource"
	CoordinatorBackend_AcquireServerStress_FullMethodName = "/rpc.CoordinatorBackend/AcquireServerStress"
)

// CoordinatorBackendClient is the client API for CoordinatorBackend service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CoordinatorBackendClient interface {
	AcquireInstanceInfo(ctx context.Context, in *AcquireInstanceInfoRequest, opts ...grpc.CallOption) (*AcquireInstanceInfoReply, error)
	AllocateIPResource(ctx context.Context, in *AllocateIPResourceRequest, opts ...grpc.CallOption) (*AllocateIPResourceReply, error)
	ReleaseIPResource(ctx context.Context, in *ReleaseIPResourceRequest, opts ...grpc.CallOption) (*ReleasePodIPReply, error)
	AllocateNetworkCard(ctx context.Context, in *AllocateNetworkCardRequest, opts ...grpc.CallOption) (*AllocateNetworkCardReply, error)
	ReleaseNetworkCard(ctx context.Context, in *ReleaseNetworkCardRequest, opts ...grpc.CallOption) (*ReleaseNetworkCardReply, error)
	TransferIPResource(ctx context.Context, in *TransferIPResourceRequest, opts ...grpc.CallOption) (*TransferIPResourceReply, error)
	AcquireServerStress(ctx context.Context, in *AcquireServerStressRequest, opts ...grpc.CallOption) (*AcquireServerStressReply, error)
}

type coordinatorBackendClient struct {
	cc grpc.ClientConnInterface
}

func NewCoordinatorBackendClient(cc grpc.ClientConnInterface) CoordinatorBackendClient {
	return &coordinatorBackendClient{cc}
}

func (c *coordinatorBackendClient) AcquireInstanceInfo(ctx context.Context, in *AcquireInstanceInfoRequest, opts ...grpc.CallOption) (*AcquireInstanceInfoReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AcquireInstanceInfoReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_AcquireInstanceInfo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) AllocateIPResource(ctx context.Context, in *AllocateIPResourceRequest, opts ...grpc.CallOption) (*AllocateIPResourceReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AllocateIPResourceReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_AllocateIPResource_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) ReleaseIPResource(ctx context.Context, in *ReleaseIPResourceRequest, opts ...grpc.CallOption) (*ReleasePodIPReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ReleasePodIPReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_ReleaseIPResource_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) AllocateNetworkCard(ctx context.Context, in *AllocateNetworkCardRequest, opts ...grpc.CallOption) (*AllocateNetworkCardReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AllocateNetworkCardReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_AllocateNetworkCard_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) ReleaseNetworkCard(ctx context.Context, in *ReleaseNetworkCardRequest, opts ...grpc.CallOption) (*ReleaseNetworkCardReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ReleaseNetworkCardReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_ReleaseNetworkCard_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) TransferIPResource(ctx context.Context, in *TransferIPResourceRequest, opts ...grpc.CallOption) (*TransferIPResourceReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(TransferIPResourceReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_TransferIPResource_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *coordinatorBackendClient) AcquireServerStress(ctx context.Context, in *AcquireServerStressRequest, opts ...grpc.CallOption) (*AcquireServerStressReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AcquireServerStressReply)
	err := c.cc.Invoke(ctx, CoordinatorBackend_AcquireServerStress_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CoordinatorBackendServer is the server API for CoordinatorBackend service.
// All implementations must embed UnimplementedCoordinatorBackendServer
// for forward compatibility
type CoordinatorBackendServer interface {
	AcquireInstanceInfo(context.Context, *AcquireInstanceInfoRequest) (*AcquireInstanceInfoReply, error)
	AllocateIPResource(context.Context, *AllocateIPResourceRequest) (*AllocateIPResourceReply, error)
	ReleaseIPResource(context.Context, *ReleaseIPResourceRequest) (*ReleasePodIPReply, error)
	AllocateNetworkCard(context.Context, *AllocateNetworkCardRequest) (*AllocateNetworkCardReply, error)
	ReleaseNetworkCard(context.Context, *ReleaseNetworkCardRequest) (*ReleaseNetworkCardReply, error)
	TransferIPResource(context.Context, *TransferIPResourceRequest) (*TransferIPResourceReply, error)
	AcquireServerStress(context.Context, *AcquireServerStressRequest) (*AcquireServerStressReply, error)
	mustEmbedUnimplementedCoordinatorBackendServer()
}

// UnimplementedCoordinatorBackendServer must be embedded to have forward compatible implementations.
type UnimplementedCoordinatorBackendServer struct {
}

func (UnimplementedCoordinatorBackendServer) AcquireInstanceInfo(context.Context, *AcquireInstanceInfoRequest) (*AcquireInstanceInfoReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AcquireInstanceInfo not implemented")
}
func (UnimplementedCoordinatorBackendServer) AllocateIPResource(context.Context, *AllocateIPResourceRequest) (*AllocateIPResourceReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllocateIPResource not implemented")
}
func (UnimplementedCoordinatorBackendServer) ReleaseIPResource(context.Context, *ReleaseIPResourceRequest) (*ReleasePodIPReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReleaseIPResource not implemented")
}
func (UnimplementedCoordinatorBackendServer) AllocateNetworkCard(context.Context, *AllocateNetworkCardRequest) (*AllocateNetworkCardReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllocateNetworkCard not implemented")
}
func (UnimplementedCoordinatorBackendServer) ReleaseNetworkCard(context.Context, *ReleaseNetworkCardRequest) (*ReleaseNetworkCardReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReleaseNetworkCard not implemented")
}
func (UnimplementedCoordinatorBackendServer) TransferIPResource(context.Context, *TransferIPResourceRequest) (*TransferIPResourceReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TransferIPResource not implemented")
}
func (UnimplementedCoordinatorBackendServer) AcquireServerStress(context.Context, *AcquireServerStressRequest) (*AcquireServerStressReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AcquireServerStress not implemented")
}
func (UnimplementedCoordinatorBackendServer) mustEmbedUnimplementedCoordinatorBackendServer() {}

// UnsafeCoordinatorBackendServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CoordinatorBackendServer will
// result in compilation errors.
type UnsafeCoordinatorBackendServer interface {
	mustEmbedUnimplementedCoordinatorBackendServer()
}

func RegisterCoordinatorBackendServer(s grpc.ServiceRegistrar, srv CoordinatorBackendServer) {
	s.RegisterService(&CoordinatorBackend_ServiceDesc, srv)
}

func _CoordinatorBackend_AcquireInstanceInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AcquireInstanceInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).AcquireInstanceInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_AcquireInstanceInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).AcquireInstanceInfo(ctx, req.(*AcquireInstanceInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_AllocateIPResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AllocateIPResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).AllocateIPResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_AllocateIPResource_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).AllocateIPResource(ctx, req.(*AllocateIPResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_ReleaseIPResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReleaseIPResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).ReleaseIPResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_ReleaseIPResource_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).ReleaseIPResource(ctx, req.(*ReleaseIPResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_AllocateNetworkCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AllocateNetworkCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).AllocateNetworkCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_AllocateNetworkCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).AllocateNetworkCard(ctx, req.(*AllocateNetworkCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_ReleaseNetworkCard_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReleaseNetworkCardRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).ReleaseNetworkCard(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_ReleaseNetworkCard_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).ReleaseNetworkCard(ctx, req.(*ReleaseNetworkCardRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_TransferIPResource_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TransferIPResourceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).TransferIPResource(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_TransferIPResource_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).TransferIPResource(ctx, req.(*TransferIPResourceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CoordinatorBackend_AcquireServerStress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AcquireServerStressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorBackendServer).AcquireServerStress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CoordinatorBackend_AcquireServerStress_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorBackendServer).AcquireServerStress(ctx, req.(*AcquireServerStressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CoordinatorBackend_ServiceDesc is the grpc.ServiceDesc for CoordinatorBackend service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CoordinatorBackend_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "rpc.CoordinatorBackend",
	HandlerType: (*CoordinatorBackendServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AcquireInstanceInfo",
			Handler:    _CoordinatorBackend_AcquireInstanceInfo_Handler,
		},
		{
			MethodName: "AllocateIPResource",
			Handler:    _CoordinatorBackend_AllocateIPResource_Handler,
		},
		{
			MethodName: "ReleaseIPResource",
			Handler:    _CoordinatorBackend_ReleaseIPResource_Handler,
		},
		{
			MethodName: "AllocateNetworkCard",
			Handler:    _CoordinatorBackend_AllocateNetworkCard_Handler,
		},
		{
			MethodName: "ReleaseNetworkCard",
			Handler:    _CoordinatorBackend_ReleaseNetworkCard_Handler,
		},
		{
			MethodName: "TransferIPResource",
			Handler:    _CoordinatorBackend_TransferIPResource_Handler,
		},
		{
			MethodName: "AcquireServerStress",
			Handler:    _CoordinatorBackend_AcquireServerStress_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rpc/raptor.proto",
}
