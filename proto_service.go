package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
)

var msgMap = make(map[string]*desc.MessageDescriptor)
var packetIdMap map[uint16]string
var packetNameMap = make(map[string]uint16)
var protoParser = protoparse.Parser{}

func InitProto() {
	packetIdFile, _ := os.ReadFile("./data/packetIds.json")
	err := json.Unmarshal(packetIdFile, &packetIdMap)
	if err != nil {
		log.Fatalln("Could not load ./data/packetIds.json", err)
	}

	for k, v := range packetIdMap {
		packetNameMap[v] = k
	}

	protoParser.ImportPaths = []string{"./data/"}
	LoadProto("OverField")
}

func LoadProto(protoName string) {
	fileDesc, err := protoParser.ParseFiles(protoName + ".proto")
	if err != nil {
		log.Println("Could not load proto file", protoName, err)
	}

	for _, fd := range fileDesc {
		for _, msg := range fd.GetMessageTypes() {
			getNestedRecursionsNum = 0
			getNestedMessage(msg)
			msgMap[msg.GetName()] = msg
		}
	}
}

var getNestedRecursionsNum = 0

func getNestedMessage(msg *desc.MessageDescriptor) {
	getNestedRecursionsNum++
	if getNestedRecursionsNum > 20 {
		return
	}
	for _, nestedMessage := range msg.GetNestedMessageTypes() {
		if len(nestedMessage.GetNestedMessageTypes()) > 0 {
			getNestedMessage(nestedMessage)
		}
		msgMap[nestedMessage.GetName()] = nestedMessage
	}
}

func GetProtoById(id uint16) *desc.MessageDescriptor {
	protoName, ok := packetIdMap[id]
	if !ok {
		return nil
	}
	return msgMap[protoName]
}

func GetProtoNameById(id uint16) string {
	protoName, ok := packetIdMap[id]
	if !ok {
		return ""
	}
	return protoName
}

func parseProto(id uint16, data []byte) (*dynamic.Message, error) {
	msg := GetProtoById(id)
	if msg == nil {
		return nil, errors.New("not found")
	}
	dMsg := dynamic.NewMessage(msg)

	err := dMsg.Unmarshal(data)
	return dMsg, err
}

func parseProtoByName(name string, data []byte) (*dynamic.Message, error) {
	msg, ok := msgMap[name]
	if !ok {
		return nil, errors.New("not found")
	}
	dMsg := dynamic.NewMessage(msg)

	err := dMsg.Unmarshal(data)
	return dMsg, err
}

func parseProtoToJson(id uint16, data []byte) (string, error) {
	dMsg, err := parseProto(id, data)
	if err != nil {
		return "", err
	}

	marshalJSON, err := dMsg.MarshalJSON()
	if err != nil {
		return "", err
	}

	return string(marshalJSON), nil
}

func parseProtoToInterface(id uint16, data []byte) (*interface{}, error) {
	object, err := parseProtoToJson(id, data)
	if err != nil {
		return nil, err
	}

	var result *interface{}
	err = json.Unmarshal([]byte(object), &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
