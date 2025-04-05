package main

import (
	"reflect"
	"sync"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
)

type PacketHead struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache

	PacketId       uint32 `protobuf:"varint,1,opt,name=packet_id,json=packetId,proto3" json:"packet_id,omitempty"`
	MsgId          uint32 `protobuf:"varint,2,opt,name=msg_id,json=msgId,proto3" json:"msg_id,omitempty"`
	Flag           uint32 `protobuf:"varint,3,opt,name=flag,proto3" json:"flag,omitempty"`
	BodyLen        uint32 `protobuf:"varint,4,opt,name=body_len,json=bodyLen,proto3" json:"body_len,omitempty"`
	TotalPackCount uint32 `protobuf:"varint,5,opt,name=total_pack_count,json=totalPackCount,proto3" json:"total_pack_count,omitempty"`
	SeqId          uint32 `protobuf:"varint,6,opt,name=seq_id,json=seqId,proto3" json:"seq_id,omitempty"`
}

var File_PacketHead_proto protoreflect.FileDescriptor
var file_PacketHead_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PacketHead_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x4f, 0x76, 0x65, 0x72, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0xb0, 0x01, 0x0a, 0x0a, 0x50, 0x61, 0x63, 0x6b,
	0x65, 0x74, 0x48, 0x65, 0x61, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x61, 0x63, 0x6b, 0x65,
	0x74, 0x49, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x6d, 0x73, 0x67, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x73, 0x67, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x6c,
	0x61, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x66, 0x6c, 0x61, 0x67, 0x12, 0x19,
	0x0a, 0x08, 0x62, 0x6f, 0x64, 0x79, 0x5f, 0x6c, 0x65, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x62, 0x6f, 0x64, 0x79, 0x4c, 0x65, 0x6e, 0x12, 0x28, 0x0a, 0x10, 0x74, 0x6f, 0x74,
	0x61, 0x6c, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0e, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x50, 0x61, 0x63, 0x6b, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x73, 0x65, 0x71, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x65, 0x71, 0x49, 0x64, 0x42, 0x09, 0x5a, 0x07, 0x2e, 0x2f,
	0x3b, 0x6d, 0x61, 0x69, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PacketHead_proto_rawDescOnce sync.Once
	file_PacketHead_proto_rawDescData = file_PacketHead_proto_rawDesc
)

func file_PacketHead_proto_rawDescGZIP() []byte {
	file_PacketHead_proto_rawDescOnce.Do(func() {
		file_PacketHead_proto_rawDescData = protoimpl.X.CompressGZIP(file_PacketHead_proto_rawDescData)
	})
	return file_PacketHead_proto_rawDescData
}

var file_PacketHead_proto_goTypes = []any{
	(*PacketHead)(nil), // 0: main.PacketHead
}
var file_PacketHead_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_PacketHead_proto_init() }
func file_PacketHead_proto_init() {
	if File_PacketHead_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_PacketHead_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PacketHead_proto_goTypes,
		DependencyIndexes: file_PacketHead_proto_depIdxs,
		MessageInfos:      file_PacketHead_proto_msgTypes,
	}.Build()
	File_PacketHead_proto = out.File
	file_PacketHead_proto_rawDesc = nil
	file_PacketHead_proto_goTypes = nil
	file_PacketHead_proto_depIdxs = nil
}

func (x *PacketHead) Reset() {
	*x = PacketHead{}
	mi := &file_PacketHead_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PacketHead) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PacketHead) ProtoMessage() {}

func (x *PacketHead) ProtoReflect() protoreflect.Message {
	mi := &file_PacketHead_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*PacketHead) Descriptor() ([]byte, []int) {
	return file_PacketHead_proto_rawDescGZIP(), []int{0}
}
