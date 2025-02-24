package tcphandler

import (
	"fmt"
	"http-server/tcp-parser"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

type TCPSenderData struct {
	SegmentsToSend  [][]byte
	DestinationPort uint16
}

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) (*TCPSenderData, error) {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return nil, err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil, nil
	}

	fmt.Println("Received TCP Package:")
	tcpparser.PrintTcpSegment(tcpSegment)
	// For SYN packets, respond with SYN-ACK
	//if tcpSegment.Flags == tcpparser.TCPFlagSYN {
	testRes := tcpparser.TCPSegment{
		SourcePort:      uint16(config.Port),
		DestinationPort: tcpSegment.SourcePort,
		SequenceNumber:  0x12345678, // Use a valid initial sequence number
		AckNumber:       tcpSegment.SequenceNumber + 1,
		Flags:           tcpparser.TCPFlagSYN | tcpparser.TCPFlagACK,
		WindowSize:      65535, // Use a standard window size
		UrgentPtr:       0,
		Options:         make([]byte, 0), // Copy options from request
		Payload:         make([]byte, 0),
	}

	senderIpPseudoHeader := &tcpparser.IPPseudoHeaderData{
		SourceIP:      ipPseudoHeaderData.DestinationIP,
		DestinationIP: ipPseudoHeaderData.SourceIP,
		Protocol:      ipPseudoHeaderData.Protocol,
		TotalLength:   20 + uint16(len(testRes.Options)) + uint16(len(testRes.Payload)),
	}

	parsedTcpPackage := tcpparser.ParseTCPSegmentToBytes(&testRes, senderIpPseudoHeader)
	resData := make([][]byte, 0)
	resData = append(resData, parsedTcpPackage)

	res := &TCPSenderData{
		SegmentsToSend:  resData,
		DestinationPort: tcpSegment.SourcePort,
	}

	return res, nil
	//}
	return nil, nil

}
