package ipparser

import (
	"http-server/helper/test"
	"testing"
)

func TestParseIPPaketV4(t *testing.T) {
	t.Run("cannot parse IPv6 package", func(t *testing.T) {
		ipV6Package := []byte{0x60, 0x6, 0xca, 0xef, 0x0, 0x20, 0x6, 0x3c, 0x2a, 0x2, 0x26, 0xf0, 0xab, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb8, 0x19, 0x32, 0xc8, 0x20, 0x1, 0x9, 0xe8, 0x53, 0xdf, 0x2, 0x0, 0x80, 0x13, 0xe7, 0x97, 0x29, 0x94, 0xd9, 0x24, 0x1, 0xbb, 0xa2, 0x8e, 0x14, 0x9d, 0xa0, 0xdb, 0x6d, 0xdf, 0x7f, 0x5c, 0x80, 0x11, 0x1, 0xf5, 0x26, 0x44, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xb2, 0x0, 0x47, 0x63, 0x6c, 0x73, 0xd0, 0xac}
		_, err := ParseIPPaket(ipV6Package)
		test.AssertError(t, err, "unsupported IP version: 6")
	})

	t.Run("parse valid IPv4 package", func(t *testing.T) {
		iPv4Package := []byte{0x45, 0x0, 0x0, 0x34, 0xfe, 0xbf, 0x40, 0x0, 0x40, 0x6, 0x3f, 0xfb, 0xc0, 0xa8, 0xb2, 0x33, 0x12, 0xeb, 0x76, 0x42, 0x9e, 0x92, 0x1, 0xbb, 0xce, 0x84, 0x2e, 0xe6, 0xe1, 0x4b, 0x72, 0x2f, 0x80, 0x10, 0x1, 0xe2, 0xfc, 0x2f, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x96, 0x4e, 0x5a, 0xf9, 0x1c, 0x3c, 0xa1, 0xf1}

		_, err := ParseIPPaket(iPv4Package)
		test.AssertNoError(t, err)
	})

	t.Run("check for invalid ip flag", func(t *testing.T) {
		iPv4Package := []byte{0x45, 0x0, 0x0, 0x34, 0xfe, 0xbf, 0x44, 0x0, 0x40, 0x6, 0x3f, 0xfb, 0xc0, 0xa8, 0xb2, 0x33, 0x12, 0xeb, 0x76, 0x42, 0x9e, 0x92, 0x1, 0xbb, 0xce, 0x84, 0x2e, 0xe6, 0xe1, 0x4b, 0x72, 0x2f, 0x80, 0x10, 0x1, 0xe2, 0xfc, 0x2f, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x96, 0x4e, 0x5a, 0xf9, 0x1c, 0x3c, 0xa1, 0xf1}

		_, err := ParseIPPaket(iPv4Package)
		test.AssertError(t, err, "invalid ip package: first Bit of IP Flags is not zero")
	})

	t.Run("checksum should be invalid", func(t *testing.T) {
		iPv4Package := []byte{0x45, 0x0, 0x0, 0x34, 0xfe, 0xbf, 0x41, 0x0, 0x40, 0x6, 0x3f, 0xfb, 0xc0, 0xa8, 0xb2, 0x33, 0x12, 0xeb, 0x76, 0x42, 0x9e, 0x92, 0x1, 0xbb, 0xce, 0x84, 0x2e, 0xe6, 0xe1, 0x4b, 0x72, 0x2f, 0x80, 0x10, 0x1, 0xe2, 0xfc, 0x2f, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x96, 0x4e, 0x5a, 0xf9, 0x1c, 0x3c, 0xa1, 0xf1}

		_, err := ParseIPPaket(iPv4Package)
		test.AssertError(t, err, "header checksum does not match: Package is dropped")
	})

	t.Run("should parse correctly", func(t *testing.T) {
		iPv4Package := []byte{69, 0, 0, 52, 254, 16, 64, 0, 108, 6, 36, 173, 104, 208, 16, 90, 192, 168, 178, 51, 1, 187, 170, 36, 14, 151, 233, 68, 185, 186, 133, 62, 128, 16, 63, 252, 221, 19, 0, 0, 1, 1, 8, 10, 10, 46, 172, 32, 69, 79, 143, 84}

		res, err := ParseIPPaket(iPv4Package)
		test.AssertNoError(t, err)
		test.AssertSliceEquality(t, []byte{res.DestinationIP[0], res.DestinationIP[1], res.DestinationIP[2], res.DestinationIP[3]}, []byte{192, 168, 178, 51})
		test.AssertSliceEquality(t, []byte{res.SourceIP[0], res.SourceIP[1], res.SourceIP[2], res.SourceIP[3]}, []byte{104, 208, 16, 90})
		test.AssertEquality(t, res.Dscp, DefaultDSCP)
		test.AssertEquality(t, res.Ecn, NonECT)
		test.AssertEquality(t, res.Identification, -496)
		test.AssertEquality(t, res.MoreFracmentsFollow, false)
		test.AssertEquality(t, res.DontFracment, true)
		test.AssertEquality(t, res.FragmentOffset, 0)
		test.AssertEquality(t, res.TimeToLive, 108)
		test.AssertEquality(t, res.Protocol, TCP)
	})

	t.Run("should parse correctly back to bytes", func(t *testing.T) {

		ipPaket := IPPaket{
			//IpHeaderBytesLength: 20,
			Dscp: 0,
			Ecn:  0,
			//TotalLength:         52,
			Identification:      -21006,
			DontFracment:        true,
			MoreFracmentsFollow: false,
			FragmentOffset:      0,
			TimeToLive:          64,
			Protocol:            TCP,
			//Checksum:            13918,
			SourceIP:      [4]byte{192, 168, 178, 48},
			DestinationIP: [4]byte{54, 83, 173, 71},
			Payload:       []byte{0x83, 0x4e, 0x22, 0xb4, 0x6f, 0x90, 0x95, 0xd5, 0xf5, 0xfc, 0xf4, 0xb9, 0x80, 0x10, 0x1, 0xbf, 0x56, 0x9a, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xf3, 0x94, 0x61, 0xfe, 0x13, 0xa1, 0xd1, 0xaa},
		}

		expected := []byte{0x45, 0x0, 0x0, 0x34, 0xad, 0xf2, 0x40, 0x0, 0x40, 0x6, 0x36, 0x5e, 0xc0, 0xa8, 0xb2, 0x30, 0x36, 0x53, 0xad, 0x47, 0x83, 0x4e, 0x22, 0xb4, 0x6f, 0x90, 0x95, 0xd5, 0xf5, 0xfc, 0xf4, 0xb9, 0x80, 0x10, 0x1, 0xbf, 0x56, 0x9a, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0xf3, 0x94, 0x61, 0xfe, 0x13, 0xa1, 0xd1, 0xaa}

		res, err := ParseIPPaketToBytes(&ipPaket)
		test.AssertNoError(t, err)
		test.AssertSliceEquality(t, res, expected)

	})
}
