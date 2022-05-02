//
// Copyright 2016-2022 Fraunhofer AISEC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//           $$\                           $$\ $$\   $$\
//           $$ |                          $$ |\__|  $$ |
//  $$$$$$$\ $$ | $$$$$$\  $$\   $$\  $$$$$$$ |$$\ $$$$$$\    $$$$$$\   $$$$$$\
// $$  _____|$$ |$$  __$$\ $$ |  $$ |$$  __$$ |$$ |\_$$  _|  $$  __$$\ $$  __$$\
// $$ /      $$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ |    $$ /  $$ |$$ | \__|
// $$ |      $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$\ $$ |  $$ |$$ |
// \$$$$$$\  $$ |\$$$$$   |\$$$$$   |\$$$$$$  |$$ |  \$$$   |\$$$$$   |$$ |
//  \_______|\__| \______/  \______/  \_______|\__|   \____/  \______/ \__|
//
// This file is part of Clouditor Community Edition.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.20.0
// source: api/discovery/discovery.proto

package discovery

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StartDiscoveryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StartDiscoveryRequest) Reset() {
	*x = StartDiscoveryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_discovery_discovery_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StartDiscoveryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StartDiscoveryRequest) ProtoMessage() {}

func (x *StartDiscoveryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_discovery_discovery_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StartDiscoveryRequest.ProtoReflect.Descriptor instead.
func (*StartDiscoveryRequest) Descriptor() ([]byte, []int) {
	return file_api_discovery_discovery_proto_rawDescGZIP(), []int{0}
}

type StartDiscoveryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Successful bool `protobuf:"varint,1,opt,name=successful,proto3" json:"successful,omitempty"`
}

func (x *StartDiscoveryResponse) Reset() {
	*x = StartDiscoveryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_discovery_discovery_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StartDiscoveryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StartDiscoveryResponse) ProtoMessage() {}

func (x *StartDiscoveryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_discovery_discovery_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StartDiscoveryResponse.ProtoReflect.Descriptor instead.
func (*StartDiscoveryResponse) Descriptor() ([]byte, []int) {
	return file_api_discovery_discovery_proto_rawDescGZIP(), []int{1}
}

func (x *StartDiscoveryResponse) GetSuccessful() bool {
	if x != nil {
		return x.Successful
	}
	return false
}

type QueryRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FilteredType string `protobuf:"bytes,1,opt,name=filtered_type,json=filteredType,proto3" json:"filtered_type,omitempty"`
	PageSize     int32  `protobuf:"varint,2,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	PageToken    string `protobuf:"bytes,3,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
}

func (x *QueryRequest) Reset() {
	*x = QueryRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_discovery_discovery_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryRequest) ProtoMessage() {}

func (x *QueryRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_discovery_discovery_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryRequest.ProtoReflect.Descriptor instead.
func (*QueryRequest) Descriptor() ([]byte, []int) {
	return file_api_discovery_discovery_proto_rawDescGZIP(), []int{2}
}

func (x *QueryRequest) GetFilteredType() string {
	if x != nil {
		return x.FilteredType
	}
	return ""
}

func (x *QueryRequest) GetPageSize() int32 {
	if x != nil {
		return x.PageSize
	}
	return 0
}

func (x *QueryRequest) GetPageToken() string {
	if x != nil {
		return x.PageToken
	}
	return ""
}

type QueryResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Results       *structpb.ListValue `protobuf:"bytes,1,opt,name=results,proto3" json:"results,omitempty"`
	NextPageToken string              `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
}

func (x *QueryResponse) Reset() {
	*x = QueryResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_discovery_discovery_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QueryResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QueryResponse) ProtoMessage() {}

func (x *QueryResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_discovery_discovery_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QueryResponse.ProtoReflect.Descriptor instead.
func (*QueryResponse) Descriptor() ([]byte, []int) {
	return file_api_discovery_discovery_proto_rawDescGZIP(), []int{3}
}

func (x *QueryResponse) GetResults() *structpb.ListValue {
	if x != nil {
		return x.Results
	}
	return nil
}

func (x *QueryResponse) GetNextPageToken() string {
	if x != nil {
		return x.NextPageToken
	}
	return ""
}

var File_api_discovery_discovery_proto protoreflect.FileDescriptor

var file_api_discovery_discovery_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x61, 0x70, 0x69, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f,
	0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x09, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x17, 0x0a, 0x15, 0x53, 0x74, 0x61, 0x72, 0x74, 0x44,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0x38, 0x0a, 0x16, 0x53, 0x74, 0x61, 0x72, 0x74, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72,
	0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x75, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x73,
	0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x66, 0x75, 0x6c, 0x22, 0x6f, 0x0a, 0x0c, 0x51, 0x75, 0x65,
	0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x66, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x65, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x65, 0x64, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x70,
	0x61, 0x67, 0x65, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x70, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0x6d, 0x0a, 0x0d, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x34, 0x0a, 0x07, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4c,
	0x69, 0x73, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x73, 0x12, 0x26, 0x0a, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x5f, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65, 0x78, 0x74,
	0x50, 0x61, 0x67, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x32, 0xdb, 0x01, 0x0a, 0x09, 0x44, 0x69,
	0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x12, 0x6f, 0x0a, 0x05, 0x53, 0x74, 0x61, 0x72, 0x74,
	0x12, 0x20, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x21, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x53,
	0x74, 0x61, 0x72, 0x74, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x21, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x22, 0x13, 0x2f,
	0x76, 0x31, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x3a, 0x01, 0x2a, 0x62, 0x01, 0x2a, 0x12, 0x5d, 0x0a, 0x05, 0x51, 0x75, 0x65, 0x72,
	0x79, 0x12, 0x17, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75,
	0x65, 0x72, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x51, 0x75, 0x65, 0x72, 0x79, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x21, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x22, 0x13, 0x2f, 0x76,
	0x31, 0x2f, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2f, 0x71, 0x75, 0x65, 0x72,
	0x79, 0x3a, 0x01, 0x2a, 0x62, 0x01, 0x2a, 0x42, 0x0f, 0x5a, 0x0d, 0x61, 0x70, 0x69, 0x2f, 0x64,
	0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_discovery_discovery_proto_rawDescOnce sync.Once
	file_api_discovery_discovery_proto_rawDescData = file_api_discovery_discovery_proto_rawDesc
)

func file_api_discovery_discovery_proto_rawDescGZIP() []byte {
	file_api_discovery_discovery_proto_rawDescOnce.Do(func() {
		file_api_discovery_discovery_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_discovery_discovery_proto_rawDescData)
	})
	return file_api_discovery_discovery_proto_rawDescData
}

var file_api_discovery_discovery_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_api_discovery_discovery_proto_goTypes = []interface{}{
	(*StartDiscoveryRequest)(nil),  // 0: clouditor.StartDiscoveryRequest
	(*StartDiscoveryResponse)(nil), // 1: clouditor.StartDiscoveryResponse
	(*QueryRequest)(nil),           // 2: clouditor.QueryRequest
	(*QueryResponse)(nil),          // 3: clouditor.QueryResponse
	(*structpb.ListValue)(nil),     // 4: google.protobuf.ListValue
}
var file_api_discovery_discovery_proto_depIdxs = []int32{
	4, // 0: clouditor.QueryResponse.results:type_name -> google.protobuf.ListValue
	0, // 1: clouditor.Discovery.Start:input_type -> clouditor.StartDiscoveryRequest
	2, // 2: clouditor.Discovery.Query:input_type -> clouditor.QueryRequest
	1, // 3: clouditor.Discovery.Start:output_type -> clouditor.StartDiscoveryResponse
	3, // 4: clouditor.Discovery.Query:output_type -> clouditor.QueryResponse
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_discovery_discovery_proto_init() }
func file_api_discovery_discovery_proto_init() {
	if File_api_discovery_discovery_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_discovery_discovery_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StartDiscoveryRequest); i {
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
		file_api_discovery_discovery_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StartDiscoveryResponse); i {
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
		file_api_discovery_discovery_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryRequest); i {
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
		file_api_discovery_discovery_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QueryResponse); i {
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
			RawDescriptor: file_api_discovery_discovery_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_discovery_discovery_proto_goTypes,
		DependencyIndexes: file_api_discovery_discovery_proto_depIdxs,
		MessageInfos:      file_api_discovery_discovery_proto_msgTypes,
	}.Build()
	File_api_discovery_discovery_proto = out.File
	file_api_discovery_discovery_proto_rawDesc = nil
	file_api_discovery_discovery_proto_goTypes = nil
	file_api_discovery_discovery_proto_depIdxs = nil
}
