// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v3.12.4
// source: sync_value.proto

package main

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sync_value_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_sync_value_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_sync_value_proto_rawDescGZIP(), []int{0}
}

type ValueRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   int32 `protobuf:"varint,1,opt,name=key,proto3" json:"key,omitempty"`
	Value int32 `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
	Type  int32 `protobuf:"varint,3,opt,name=type,proto3" json:"type,omitempty"`
	Mapid int32 `protobuf:"varint,4,opt,name=mapid,proto3" json:"mapid,omitempty"`
}

func (x *ValueRequest) Reset() {
	*x = ValueRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sync_value_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValueRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValueRequest) ProtoMessage() {}

func (x *ValueRequest) ProtoReflect() protoreflect.Message {
	mi := &file_sync_value_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValueRequest.ProtoReflect.Descriptor instead.
func (*ValueRequest) Descriptor() ([]byte, []int) {
	return file_sync_value_proto_rawDescGZIP(), []int{1}
}

func (x *ValueRequest) GetKey() int32 {
	if x != nil {
		return x.Key
	}
	return 0
}

func (x *ValueRequest) GetValue() int32 {
	if x != nil {
		return x.Value
	}
	return 0
}

func (x *ValueRequest) GetType() int32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *ValueRequest) GetMapid() int32 {
	if x != nil {
		return x.Mapid
	}
	return 0
}

type ValueResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key   int32 `protobuf:"varint,1,opt,name=key,proto3" json:"key,omitempty"`
	Value int32 `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
	Type  int32 `protobuf:"varint,3,opt,name=type,proto3" json:"type,omitempty"`
	Mapid int32 `protobuf:"varint,4,opt,name=mapid,proto3" json:"mapid,omitempty"`
}

func (x *ValueResponse) Reset() {
	*x = ValueResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sync_value_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValueResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValueResponse) ProtoMessage() {}

func (x *ValueResponse) ProtoReflect() protoreflect.Message {
	mi := &file_sync_value_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValueResponse.ProtoReflect.Descriptor instead.
func (*ValueResponse) Descriptor() ([]byte, []int) {
	return file_sync_value_proto_rawDescGZIP(), []int{2}
}

func (x *ValueResponse) GetKey() int32 {
	if x != nil {
		return x.Key
	}
	return 0
}

func (x *ValueResponse) GetValue() int32 {
	if x != nil {
		return x.Value
	}
	return 0
}

func (x *ValueResponse) GetType() int32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *ValueResponse) GetMapid() int32 {
	if x != nil {
		return x.Mapid
	}
	return 0
}

var File_sync_value_proto protoreflect.FileDescriptor

var file_sync_value_proto_rawDesc = []byte{
	0x0a, 0x10, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0x07, 0x0a, 0x05, 0x45, 0x6d, 0x70, 0x74,
	0x79, 0x22, 0x60, 0x0a, 0x0c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a,
	0x05, 0x6d, 0x61, 0x70, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x6d, 0x61,
	0x70, 0x69, 0x64, 0x22, 0x61, 0x0a, 0x0d, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x70, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x05, 0x6d, 0x61, 0x70, 0x69, 0x64, 0x32, 0x68, 0x0a, 0x0b, 0x53, 0x79, 0x6e, 0x63, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x47, 0x65, 0x74, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x12, 0x0b, 0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x13,
	0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x08, 0x53, 0x65, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x12,
	0x12, 0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x0b, 0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x42, 0x1e, 0x5a, 0x1c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64,
	0x6f, 0x72, 0x6b, 0x61, 0x6d, 0x6f, 0x74, 0x6f, 0x72, 0x6b, 0x61, 0x2f, 0x6d, 0x61, 0x69, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_sync_value_proto_rawDescOnce sync.Once
	file_sync_value_proto_rawDescData = file_sync_value_proto_rawDesc
)

func file_sync_value_proto_rawDescGZIP() []byte {
	file_sync_value_proto_rawDescOnce.Do(func() {
		file_sync_value_proto_rawDescData = protoimpl.X.CompressGZIP(file_sync_value_proto_rawDescData)
	})
	return file_sync_value_proto_rawDescData
}

var file_sync_value_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_sync_value_proto_goTypes = []any{
	(*Empty)(nil),         // 0: main.Empty
	(*ValueRequest)(nil),  // 1: main.ValueRequest
	(*ValueResponse)(nil), // 2: main.ValueResponse
}
var file_sync_value_proto_depIdxs = []int32{
	0, // 0: main.SyncService.GetValue:input_type -> main.Empty
	1, // 1: main.SyncService.SetValue:input_type -> main.ValueRequest
	2, // 2: main.SyncService.GetValue:output_type -> main.ValueResponse
	0, // 3: main.SyncService.SetValue:output_type -> main.Empty
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_sync_value_proto_init() }
func file_sync_value_proto_init() {
	if File_sync_value_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_sync_value_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Empty); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sync_value_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*ValueRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_sync_value_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*ValueResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_sync_value_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_sync_value_proto_goTypes,
		DependencyIndexes: file_sync_value_proto_depIdxs,
		MessageInfos:      file_sync_value_proto_msgTypes,
	}.Build()
	File_sync_value_proto = out.File
	file_sync_value_proto_rawDesc = nil
	file_sync_value_proto_goTypes = nil
	file_sync_value_proto_depIdxs = nil
}
