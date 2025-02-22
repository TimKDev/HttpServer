package tcphandler

import (
	"http-server/tcp-parser"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) ([][]byte, error) {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return nil, err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil, nil
	}
	tcpparser.PrintTcpSegment(tcpSegment)

	//TODO Hier brachen wir eine Factory Methode, die ein TCPSegment in ein Rawumwandelt und die Lenghts und die Checksum berechnet.
	testRes := tcpparser.TCPSegment{
		SourcePort:      uint16(config.Port),
		DestinationPort: tcpSegment.SourcePort,
		SequenceNumber:  121233,
		AckNumber:       tcpSegment.AckNumber + 1,
		DataOffset:      0x04,
		Flags:           tcpparser.TCPFlagACK,
		WindowSize:      1000,
		Checksum:        0,
		UrgentPtr:       0,
		Options:         make([]byte, 0),
		Payload:         make([]byte, 0),
	}

	parsedTcpPackage := tcpparser.ParseTCPSegmentToBytes(&testRes)
	res := make([][]byte, 0)
	res = append(res, parsedTcpPackage)

	return res, nil
}
