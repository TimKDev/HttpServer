package tcpsender

import (
	"fmt"
	"http-server/ip-parser"
	"http-server/ip-sender"
	"http-server/tcp-parser"
)

type TcpDataSegment struct {
	SequenceNumber uint32
	Payload        []byte
}

type TcpSessionStatus int

const (
	WaitingForHandShake   TcpSessionStatus = 0
	ConnectionEstablished TcpSessionStatus = 1
)

type TcpSession struct {
	SourceIP           [4]byte
	DestinationIP      [4]byte
	SourcePort         uint16
	DestinationPort    uint16
	ReceivedSegments   []TcpDataSegment
	SendedSegments     []TcpDataSegment
	LastSendAck        uint32
	NextSequenceNumber uint32
	State              TcpSessionStatus
	ClientWindowSize   uint16
	ServerWindowSize   uint16
}

func SendTCPSegment(sourceIP [4]byte, destinationIP [4]byte, segment *tcpparser.TCPSegment) {

	senderIpPseudoHeader := &tcpparser.IPPseudoHeaderData{
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		Protocol:      uint8(ipparser.TCP),
		TotalLength:   20 + uint16(len(segment.Options)) + uint16(len(segment.Payload)),
	}

	parsedTcpPackage := tcpparser.ParseTCPSegmentToBytes(segment, senderIpPseudoHeader)
	ipsender.SendIPPackage(sourceIP, destinationIP, segment.DestinationPort, parsedTcpPackage)
}

func (session *TcpSession) SendTCPSegment(payload []byte) {

	tcpSegmentToSend := tcpparser.TCPSegment{
		SourcePort:      session.SourcePort,
		DestinationPort: session.DestinationPort,
		SequenceNumber:  session.NextSequenceNumber, //Wie ist diese Zahl?
		AckNumber:       session.LastSendAck,        //Wie ist diese Zahl?
		Flags:           tcpparser.TCPFlagACK,
		WindowSize:      session.ServerWindowSize,
		UrgentPtr:       0,
		Options:         make([]byte, 0),
		Payload:         payload,
	}

	fmt.Println("Send TCP Package:")
	tcpparser.PrintTcpSegment(&tcpSegmentToSend)

	senderIpPseudoHeader := &tcpparser.IPPseudoHeaderData{
		SourceIP:      session.SourceIP,
		DestinationIP: session.DestinationIP,
		Protocol:      uint8(ipparser.TCP),
		TotalLength:   20 + uint16(len(tcpSegmentToSend.Options)) + uint16(len(tcpSegmentToSend.Payload)),
	}

	parsedTcpPackage := tcpparser.ParseTCPSegmentToBytes(&tcpSegmentToSend, senderIpPseudoHeader)
	ipsender.SendIPPackage(session.SourceIP, session.DestinationIP, session.DestinationPort, parsedTcpPackage)
}
