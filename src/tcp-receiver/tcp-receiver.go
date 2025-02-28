package tcpreceiver

import (
	"fmt"
	"http-server/tcp-parser"
	"http-server/tcp-sender"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

type TcpDataSegments struct {
	SequenceNumber uint32
	Payload        []byte
}

type TcpSession struct {
	DestinationIP    [4]byte
	DestinationPort  uint16
	ReceivedSegments []TcpDataSegments
	LastSendAct      uint32
	State            tcpparser.TCPFlag
	WindowSize       uint16
}

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) error {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil
	}

	fmt.Println("Received TCP Package:")
	tcpparser.PrintTcpSegment(tcpSegment)

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

	tcpsender.SendTCPSegment(ipPseudoHeaderData.DestinationIP, ipPseudoHeaderData.SourceIP, &testRes)

	return nil

}
