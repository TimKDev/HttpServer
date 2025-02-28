package tcpsender

import (
	"http-server/ip-parser"
	"http-server/ip-sender"
	"http-server/tcp-parser"
)

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
