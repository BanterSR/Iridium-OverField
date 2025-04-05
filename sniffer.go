package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Packet struct {
	Time       int64       `json:"time"`
	FromServer bool        `json:"fromServer"`
	PacketId   uint16      `json:"packetId"`
	PacketName string      `json:"packetName"`
	Object     interface{} `json:"object"`
	Raw        []byte      `json:"raw"`
}

var headName = "PacketHead"

var captureHandler *pcap.Handle
var packetFilter = make(map[string]bool)
var pcapFile *os.File

func openPcap(fileName string) {
	var err error
	captureHandler, err = pcap.OpenOffline(fileName)
	if err != nil {
		log.Println("Could not open pacp file", err)
		return
	}
	startSniffer()
}

func openCapture() {
	var err error
	captureHandler, err = pcap.OpenLive(config.DeviceName, 1500, true, -1)

	if err != nil {
		log.Println("Could not open capture", err)
		return
	}

	if config.AutoSavePcapFiles {
		pcapFile, err = os.Create(time.Now().Format("06-01-02 15.04.05") + ".pcapng")
		if err != nil {
			log.Println("Could not create pcapng file", err)
		}
		defer pcapFile.Close()
	}

	startSniffer()
}

func closeHandle() {
	if captureHandler != nil {
		captureHandler.Close()
		captureHandler = nil
	}
	if pcapFile != nil {
		pcapFile.Close()
		pcapFile = nil
	}
}

func startSniffer() {
	defer captureHandler.Close()
	expr := fmt.Sprintf("tcp portrange %v-%v", uint16(config.MinPort), uint16(config.MaxPort))
	err := captureHandler.SetBPFFilter(expr)
	if err != nil {
		log.Println("Could not set the filter of capture")
		return
	}

	packetSource := gopacket.NewPacketSource(captureHandler, captureHandler.LinkType())
	packetSource.NoCopy = true

	var pcapWriter *pcapgo.NgWriter
	if pcapFile != nil {
		pcapWriter, err = pcapgo.NewNgWriter(pcapFile, captureHandler.LinkType())
		if err != nil {
			log.Println("Could not create pcapng writer", err)
		}
	}

	for packet := range packetSource.Packets() {
		if pcapWriter != nil {
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Could not write packet to pcap file", err)
			}
		}

		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		tcp, ok := transportLayer.(*layers.TCP)
		if !ok {
			continue
		}

		capTime := packet.Metadata().Timestamp
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		data := appLayer.Payload()

		fromServer := config.MinPort <= tcp.SrcPort && tcp.SrcPort <= config.MaxPort
		key := fmt.Sprintf("%v;%v;%v", tcp.SrcPort, tcp.DstPort, fromServer)

		addDataMap(key, data, fromServer)
		handleTcp(capTime)
	}
}

func handleTcp(capTime time.Time) {
	for key, s := range getDataMap() {
		if len(s.data) < tcpHeadSize {
			continue
		}
		// 头部长度
		headLen := binary.BigEndian.Uint16(s.data[:tcpHeadSize])
		if len(s.data) < int(headLen)+tcpHeadSize {
			continue
		}
		headBin := s.data[tcpHeadSize : int(headLen)+tcpHeadSize]

		dMsg, err := parseProtoByName(headName, headBin)
		if err != nil {
			log.Printf("Could not parse PacketHead proto Error:%s\n", err)
			delData(key, uint16(len(s.data)))
			continue
		}
		oj, err := dMsg.MarshalJSON()
		if err != nil {
			log.Printf("Could not parse PacketHead proto Error:%s\n", err)
			delData(key, uint16(len(s.data)))
			continue
		}
		var objectJson interface{}
		err = json.Unmarshal(oj, &objectJson)
		if err != nil {
			log.Printf("Could not parse PacketHead proto Error:%s\n", err)
			delData(key, uint16(len(s.data)))
			continue
		}
		head := objectJson.(map[string]interface{})
		s.handleProtoPacket(head, headLen, s.fromServer, capTime)
	}
}

func (s *session) handleProtoPacket(head map[string]interface{}, headLen uint16, fromServer bool, timestamp time.Time) {
	cmdId := head["msgId"].(float64)
	bodyLen := float64(0)
	if head["bodyLen"] != nil {
		bodyLen = head["bodyLen"].(float64)
	}

	if uint32(len(s.data)) < uint32(headLen)+uint32(bodyLen)+tcpHeadSize {
		return
	}
	bodyBin := s.data[uint32(headLen)+tcpHeadSize : uint32(headLen)+uint32(bodyLen)+tcpHeadSize]

	fmt.Println(head) // TODO log head

	objectJson, err := parseProtoToInterface(uint16(cmdId), bodyBin)
	if err != nil {
		bodyPb, err := DynamicParse(bodyBin)
		if err != nil {
			fmt.Printf("err body:%s\n", base64.StdEncoding.EncodeToString(bodyBin))
			goto to
		}
		buildPacketToSend(bodyBin, s.fromServer, timestamp, uint16(cmdId), bodyPb)
	} else {
		buildPacketToSend(bodyBin, fromServer, timestamp, uint16(cmdId), objectJson)
	}

to:
	delData(s.key, headLen+uint16(bodyLen)+tcpHeadSize)
}

func buildPacketToSend(data []byte, fromSever bool, timestamp time.Time, packetId uint16, objectJson interface{}) {
	packet := &Packet{
		Time:       timestamp.UnixMilli(),
		FromServer: fromSever,
		PacketId:   packetId,
		PacketName: GetProtoNameById(packetId),
		Object:     objectJson,
		Raw:        data,
	}

	jsonResult, err := json.Marshal(packet)
	if err != nil {
		log.Println("Json marshal error", err)
	}
	logPacket(packet)

	if packetFilter[GetProtoNameById(packetId)] {
		return
	}
	sendStreamMsg(string(jsonResult))
}

func logPacket(packet *Packet) {
	from := "[Client]"
	if packet.FromServer {
		from = "[Server]"
	}
	forward := ""
	if strings.Contains(packet.PacketName, "Rsp") {
		forward = "<--"
	} else if strings.Contains(packet.PacketName, "Req") {
		forward = "-->"
	} else if strings.Contains(packet.PacketName, "Notice") && packet.FromServer {
		forward = "<-i"
	}

	log.Println(color.GreenString(from),
		"\t",
		color.CyanString(forward),
		"\t",
		color.RedString(packet.PacketName),
		color.YellowString("#"+strconv.Itoa(int(packet.PacketId))),
		"\t",
		len(packet.Raw),
	)
}
