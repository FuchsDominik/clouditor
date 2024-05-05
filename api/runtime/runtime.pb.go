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
// 	protoc-gen-go v1.34.0
// 	protoc        (unknown)
// source: api/runtime/runtime.proto

package runtime

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Runtime struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// release_version is the latest Clouditor release version for this commit
	ReleaseVersion *string `protobuf:"bytes,1,opt,name=release_version,json=releaseVersion,proto3,oneof" json:"release_version,omitempty"`
	// vcs is the used version control system
	Vcs string `protobuf:"bytes,2,opt,name=vcs,proto3" json:"vcs,omitempty"`
	// commit_hash is the current Clouditor commit hash
	CommitHash string `protobuf:"bytes,3,opt,name=commit_hash,json=commitHash,proto3" json:"commit_hash,omitempty"`
	// commit_time is the time of the Clouditor commit
	CommitTime *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=commit_time,json=commitTime,proto3" json:"commit_time,omitempty"`
	// golang_version is the used golang version
	GolangVersion string `protobuf:"bytes,5,opt,name=golang_version,json=golangVersion,proto3" json:"golang_version,omitempty"`
	// dependency is a list of used runtime dependencies
	Dependencies []*Dependency `protobuf:"bytes,6,rep,name=dependencies,proto3" json:"dependencies,omitempty"`
}

func (x *Runtime) Reset() {
	*x = Runtime{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_runtime_runtime_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Runtime) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Runtime) ProtoMessage() {}

func (x *Runtime) ProtoReflect() protoreflect.Message {
	mi := &file_api_runtime_runtime_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Runtime.ProtoReflect.Descriptor instead.
func (*Runtime) Descriptor() ([]byte, []int) {
	return file_api_runtime_runtime_proto_rawDescGZIP(), []int{0}
}

func (x *Runtime) GetReleaseVersion() string {
	if x != nil && x.ReleaseVersion != nil {
		return *x.ReleaseVersion
	}
	return ""
}

func (x *Runtime) GetVcs() string {
	if x != nil {
		return x.Vcs
	}
	return ""
}

func (x *Runtime) GetCommitHash() string {
	if x != nil {
		return x.CommitHash
	}
	return ""
}

func (x *Runtime) GetCommitTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CommitTime
	}
	return nil
}

func (x *Runtime) GetGolangVersion() string {
	if x != nil {
		return x.GolangVersion
	}
	return ""
}

func (x *Runtime) GetDependencies() []*Dependency {
	if x != nil {
		return x.Dependencies
	}
	return nil
}

type Dependency struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Path    string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Version string `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *Dependency) Reset() {
	*x = Dependency{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_runtime_runtime_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Dependency) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dependency) ProtoMessage() {}

func (x *Dependency) ProtoReflect() protoreflect.Message {
	mi := &file_api_runtime_runtime_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dependency.ProtoReflect.Descriptor instead.
func (*Dependency) Descriptor() ([]byte, []int) {
	return file_api_runtime_runtime_proto_rawDescGZIP(), []int{1}
}

func (x *Dependency) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Dependency) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type GetRuntimeInfoRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetRuntimeInfoRequest) Reset() {
	*x = GetRuntimeInfoRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_runtime_runtime_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRuntimeInfoRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRuntimeInfoRequest) ProtoMessage() {}

func (x *GetRuntimeInfoRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_runtime_runtime_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRuntimeInfoRequest.ProtoReflect.Descriptor instead.
func (*GetRuntimeInfoRequest) Descriptor() ([]byte, []int) {
	return file_api_runtime_runtime_proto_rawDescGZIP(), []int{2}
}

var File_api_runtime_runtime_proto protoreflect.FileDescriptor

var file_api_runtime_runtime_proto_rawDesc = []byte{
	0x0a, 0x19, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x2f, 0x72, 0x75,
	0x6e, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x14, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76,
	0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa8, 0x02, 0x0a, 0x07, 0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x2c,
	0x0a, 0x0f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0e, 0x72, 0x65, 0x6c, 0x65, 0x61,
	0x73, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x10, 0x0a, 0x03,
	0x76, 0x63, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x76, 0x63, 0x73, 0x12, 0x1f,
	0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x48, 0x61, 0x73, 0x68, 0x12,
	0x3b, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0e,
	0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x12, 0x44, 0x0a, 0x0c, 0x64, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63,
	0x69, 0x65, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x52, 0x0c, 0x64, 0x65, 0x70,
	0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x69, 0x65, 0x73, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x72, 0x65,
	0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x0a,
	0x0a, 0x44, 0x65, 0x70, 0x65, 0x6e, 0x64, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x70,
	0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12,
	0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x17, 0x0a, 0x15, 0x47, 0x65, 0x74,
	0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x42, 0x2f, 0x5a, 0x2d, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2e,
	0x69, 0x6f, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x69, 0x74, 0x6f, 0x72, 0x2f, 0x76, 0x32, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x3b, 0x72, 0x75, 0x6e, 0x74,
	0x69, 0x6d, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_runtime_runtime_proto_rawDescOnce sync.Once
	file_api_runtime_runtime_proto_rawDescData = file_api_runtime_runtime_proto_rawDesc
)

func file_api_runtime_runtime_proto_rawDescGZIP() []byte {
	file_api_runtime_runtime_proto_rawDescOnce.Do(func() {
		file_api_runtime_runtime_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_runtime_runtime_proto_rawDescData)
	})
	return file_api_runtime_runtime_proto_rawDescData
}

var file_api_runtime_runtime_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_api_runtime_runtime_proto_goTypes = []interface{}{
	(*Runtime)(nil),               // 0: clouditor.runtime.v1.Runtime
	(*Dependency)(nil),            // 1: clouditor.runtime.v1.Dependency
	(*GetRuntimeInfoRequest)(nil), // 2: clouditor.runtime.v1.GetRuntimeInfoRequest
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
}
var file_api_runtime_runtime_proto_depIdxs = []int32{
	3, // 0: clouditor.runtime.v1.Runtime.commit_time:type_name -> google.protobuf.Timestamp
	1, // 1: clouditor.runtime.v1.Runtime.dependencies:type_name -> clouditor.runtime.v1.Dependency
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_api_runtime_runtime_proto_init() }
func file_api_runtime_runtime_proto_init() {
	if File_api_runtime_runtime_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_runtime_runtime_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Runtime); i {
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
		file_api_runtime_runtime_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Dependency); i {
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
		file_api_runtime_runtime_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRuntimeInfoRequest); i {
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
	file_api_runtime_runtime_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_runtime_runtime_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_runtime_runtime_proto_goTypes,
		DependencyIndexes: file_api_runtime_runtime_proto_depIdxs,
		MessageInfos:      file_api_runtime_runtime_proto_msgTypes,
	}.Build()
	File_api_runtime_runtime_proto = out.File
	file_api_runtime_runtime_proto_rawDesc = nil
	file_api_runtime_runtime_proto_goTypes = nil
	file_api_runtime_runtime_proto_depIdxs = nil
}
