package iphandler

import (
	"http-server/helper/test"
	ipparser "http-server/ip-parser"
	"testing"
)

func TestIPFragmentationCombination(t *testing.T) {
	t.Run("should correctly combine two IP fragments", func(t *testing.T) {
		// Create first fragment
		fragment1 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			Dscp:                1,
			Ecn:                 2,
			TotalLength:         40, // 20 bytes header + 20 bytes payload
			Identification:      12345,
			DontFracment:        false,
			MoreFracmentsFollow: true,
			FragmentOffset:      0,
			TimeToLive:          64,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("First part of payload."),
		}

		// Create second fragment
		fragment2 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			TotalLength:         40, // 20 bytes header + 20 bytes payload
			Identification:      12345,
			MoreFracmentsFollow: false,
			FragmentOffset:      2, // (20 bytes / 8) = 2
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("Second part of payload"),
		}

		fragments := []*ipparser.IPPaket{fragment1, fragment2}
		result := buildPackageFromFracments(fragments)

		// Verify the combined package
		test.AssertNoError(t, nil)
		test.AssertNotNil(t, result)
		test.AssertEquality(t, result.Identification, int16(12345))
		test.AssertEquality(t, result.MoreFracmentsFollow, false)
		test.AssertEquality(t, result.FragmentOffset, int16(0))
		test.AssertEquality(t, len(result.Payload), 40)
		test.AssertEquality(t, string(result.Payload), "First part of payload.Second part of payload")
	})

	t.Run("should return nil for incomplete fragments", func(t *testing.T) {
		fragment1 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			Identification:      12345,
			MoreFracmentsFollow: true,
			FragmentOffset:      0,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("First part"),
		}

		// Missing middle fragment
		fragment3 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			Identification:      12345,
			MoreFracmentsFollow: false,
			FragmentOffset:      4,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("Last part"),
		}

		fragments := []*ipparser.IPPaket{fragment1, fragment3}
		result := buildPackageFromFracments(fragments)

		test.AssertEquality(t, result == nil, true)
	})

	t.Run("should not combine fragments with different identifications", func(t *testing.T) {
		fragment1 := &ipparser.IPPaket{
			Identification:      12345,
			MoreFracmentsFollow: true,
			FragmentOffset:      0,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("First part"),
		}

		fragment2 := &ipparser.IPPaket{
			Identification:      24321, // Different identification
			MoreFracmentsFollow: false,
			FragmentOffset:      2,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte("Second part"),
		}

		fragments := []*ipparser.IPPaket{fragment1, fragment2}
		result := buildPackageFromFracments(fragments)

		test.AssertEquality(t, result == nil, true)
	})
}
