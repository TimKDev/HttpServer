package tcphandler

import (
	"http-server/tcp-parser"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) error {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil
	}
	tcpparser.PrintTcpSegment(tcpSegment)
	return nil
}
