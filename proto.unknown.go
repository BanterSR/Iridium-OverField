package main

import (
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

func DynamicParse(data []byte) (map[int]interface{}, error) {
	result := make(map[int]interface{})
	for len(data) > 0 {
		num, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, fmt.Errorf("failed to consume tag: %v", protowire.ParseError(n))
		}
		data = data[n:]
		var value interface{}
		switch wireType {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return nil, fmt.Errorf("failed to consume varint: %v", protowire.ParseError(n))
			}
			value = v
			data = data[n:]
		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(data)
			if n < 0 {
				return nil, fmt.Errorf("failed to consume fixed32: %v", protowire.ParseError(n))
			}
			value = v
			data = data[n:]
		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(data)
			if n < 0 {
				return nil, fmt.Errorf("failed to consume fixed64: %v", protowire.ParseError(n))
			}
			value = v
			data = data[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return nil, fmt.Errorf("failed to consume bytes: %v", protowire.ParseError(n))
			}
			value = processBytes(v)
			data = data[n:]
		case protowire.StartGroupType, protowire.EndGroupType:
			return nil, fmt.Errorf("groups are deprecated in proto3")
		default:
			return nil, fmt.Errorf("unknown wire type %d", wireType)
		}

		result[int(num)] = value
	}
	return result, nil
}

func processBytes(data []byte) interface{} {
	if utf8.Valid(data) {
		return string(data)
	}
	nestedMessage, err := DynamicParse(data)
	if err == nil {
		return nestedMessage
	}
	return data
}
