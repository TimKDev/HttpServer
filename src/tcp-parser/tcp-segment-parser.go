package tcpparser

import (
	"http-server/helper/bytes"
)

func ParseTCPSegmentToBytes(segment *TCPSegment, ipPseudoHeaderData *IPPseudoHeaderData) []byte {
	dataOffset := (20 + len(segment.Options)) / 4
	result := make([]byte, 0, 20)
	result = append(result, bytes.ExtractTwoBytes(segment.SourcePort)...)
	result = append(result, bytes.ExtractTwoBytes(segment.DestinationPort)...)
	result = append(result, bytes.ExtractFourBytes(segment.SequenceNumber)...)
	result = append(result, bytes.ExtractFourBytes(segment.AckNumber)...)
	result = append(result, byte(dataOffset)<<4)
	result = append(result, byte(segment.Flags))
	result = append(result, bytes.ExtractTwoBytes(segment.WindowSize)...)
	result = append(result, bytes.ExtractTwoBytes(0)...) // Set Checksum to 0
	result = append(result, bytes.ExtractTwoBytes(segment.UrgentPtr)...)
	result = append(result, segment.Options...)
	result = append(result, segment.Payload...)

	checksum := calculateChecksum(result, ipPseudoHeaderData)
	checksumInBytes := bytes.ExtractTwoBytes(checksum)
	result[16] = checksumInBytes[0]
	result[17] = checksumInBytes[1]

	return result

}
