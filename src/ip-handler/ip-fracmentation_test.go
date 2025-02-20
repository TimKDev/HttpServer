package iphandler

import (
	"http-server/helper/test"
	 "http-server/ip-parser"
	"testing"
	"time"
)

func TestIPFragmentationCombination(t *testing.T) {
	t.Run("should correctly combine two IP fragments", func(t *testing.T) {
		fragment1 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			Dscp:                1,
			Ecn:                 2,
			TotalLength:         28,
			Identification:      12345,
			DontFracment:        false,
			MoreFracmentsFollow: true,
			FragmentOffset:      0,
			TimeToLive:          64,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte{1, 1, 1, 1, 1, 1, 1, 1},
		}

		fragment2 := &ipparser.IPPaket{
			IpHeaderBytesLength: 20,
			TotalLength:         23,
			Identification:      12345,
			MoreFracmentsFollow: false,
			FragmentOffset:      1,
			Protocol:            ipparser.TCP,
			SourceIP:            [4]byte{192, 168, 1, 1},
			DestinationIP:       [4]byte{192, 168, 1, 2},
			Payload:             []byte{2, 2, 2},
		}

		input := make(map[string][]FracmentEntry)
		input["test"] = []FracmentEntry{
			{
				Package:     fragment1,
				ArrivalTime: time.Time{},
			},
			{
				Package:     fragment2,
				ArrivalTime: time.Time{},
			},
		}
		result := buildPackageFromFracments(input)

		test.AssertNoError(t, nil)
		test.AssertNotNil(t, result)
		test.AssertEquality(t, result.Identification, int16(12345))
		test.AssertEquality(t, result.MoreFracmentsFollow, false)
		test.AssertEquality(t, result.FragmentOffset, uint16(0))
		test.AssertEquality(t, len(result.Payload), 11)
		test.AssertSliceEquality(t, result.Payload, []byte{1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2})
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

		input := make(map[string][]FracmentEntry)
		input["test"] = []FracmentEntry{
			{
				Package:     fragment1,
				ArrivalTime: time.Time{},
			},
			{
				Package:     fragment3,
				ArrivalTime: time.Time{},
			},
		}
		result := buildPackageFromFracments(input)

		test.AssertEquality(t, result == nil, true)
	})
}
