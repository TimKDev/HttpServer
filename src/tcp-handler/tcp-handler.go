package tcphandler

import (
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

	//TODO Hier brachen wir eine Factory Methode, die ein TCPSegment in ein Rawumwandelt und die Lenghts und die Checksum berechnet.
	testRes := tcpparser.TCPSegment{
		SourcePort:      uint16(config.Port),
		DestinationPort: tcpSegment.SourcePort,
		SequenceNumber:  121233,
		AckNumber:       tcpSegment.SequenceNumber + 1,
		Flags:           tcpparser.TCPFlagACK | tcpparser.TCPFlagSYN,
		WindowSize:      1000,
		UrgentPtr:       0,
		Options:         make([]byte, 0),
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
}
