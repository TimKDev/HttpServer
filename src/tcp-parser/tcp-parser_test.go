package tcpparser

import (
	"http-server/helper/test"
	"testing"
)

func TestParseTCPFracment(t *testing.T) {

	t.Run("parse valid IPv4 package", func(t *testing.T) {
		tcpFracment := []byte{0xb0, 0x28, 0x0, 0x50, 0x39, 0xbf, 0x41, 0xd, 0x42, 0x40, 0xf2, 0xef, 0x80, 0x10, 0x1, 0xf4, 0x72, 0xc0, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xc7, 0x14, 0x5e, 0xc, 0x73, 0x97, 0x15, 0x19}
		iPPseudoHeaderData := &IPPseudoHeaderData{
			SourceIP:      [4]byte{192, 168, 178, 51},
			DestinationIP: [4]byte{34, 107, 221, 82},
			Protocol:      6,
			TotalLength:   32,
		}
		//Checksum Wireshark: 62440
		_, err := ParseTCPSegment(tcpFracment, iPPseudoHeaderData)
		test.AssertNoError(t, err)
	})
}
