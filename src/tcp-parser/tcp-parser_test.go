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
		_, err := ParseTCPSegment(tcpFracment, iPPseudoHeaderData, false)
		test.AssertNoError(t, err)
	})

	t.Run("calculate checksum", func(t *testing.T) {
		tcpFracment := []byte{0xb0, 0x28, 0x0, 0x50, 0x39, 0xbf, 0x41, 0xd, 0x42, 0x40, 0xf2, 0xef, 0x80, 0x10, 0x1, 0xf4, 0x72, 0xc0, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xc7, 0x14, 0x5e, 0xc, 0x73, 0x97, 0x15, 0x19}
		iPPseudoHeaderData := &IPPseudoHeaderData{
			SourceIP:      [4]byte{192, 168, 178, 51},
			DestinationIP: [4]byte{34, 107, 221, 82},
			Protocol:      6,
			TotalLength:   32,
		}
		checksumValue := calculateChecksum(tcpFracment, iPPseudoHeaderData)
		test.AssertEquality(t, checksumValue, 62440) //Here it is not possible to use the checksum that is defined in the checksum field in the TCP Header, but instead the checksum is calculate to 62440 from Wireshark. The checksum does not match in this case, because modern Network Interface Cards (NICs) verify the checksum themselfs instead of relying on the OS to do the check and write an invalid checksum into the package. This is called "TCP checksum offloading".
	})

	t.Run("parse valid tcp package and check headers", func(t *testing.T) {
		tcpFrament := []byte{0x85, 0x8c, 0x22, 0xb4, 0xb4, 0xb6, 0xe6, 0xc6, 0x43, 0xbe, 0xd7, 0x1b, 0x80, 0x10, 0x1, 0xbf, 0x8c, 0x83, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x4d, 0xc6, 0x1c, 0xc7, 0x30, 0x18, 0x97, 0xc4}

		iPPseudoHeaderData := &IPPseudoHeaderData{
			SourceIP:      [4]byte{192, 168, 178, 48},
			DestinationIP: [4]byte{18, 208, 6, 180},
			Protocol:      6,
			TotalLength:   52,
		}

		tcpFracment, err := ParseTCPSegment(tcpFrament, iPPseudoHeaderData, false)
		test.AssertNoError(t, err)
		test.AssertEquality(t, tcpFracment.SourcePort, 34188)
		test.AssertEquality(t, tcpFracment.DestinationPort, 8884)
		test.AssertEquality(t, tcpFracment.AckNumber, 1136580379)
		test.AssertEquality(t, tcpFracment.SequenceNumber, 3031885510)
		test.AssertEquality(t, tcpFracment.Checksum, 35971)
		test.AssertEquality(t, tcpFracment.DataOffset, 8)
		test.AssertEquality(t, tcpFracment.Flags, 16)
		test.AssertEquality(t, tcpFracment.WindowSize, 447)
		test.AssertEquality(t, tcpFracment.UrgentPtr, 0)
	})
}
