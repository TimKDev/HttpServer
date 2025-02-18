package tcpparser

import (
	"encoding/binary"
	"fmt"
)

type IPPseudoHeaderData struct {
	SourceIP      [4]byte
	DestinationIP [4]byte
	Protocol      uint8
	TotalLength   uint16
}

func ParseTCPSegmentToBytes(segment *TCPSegment) []byte {
	result := make([]byte, 0, 20)
	result = append(result, extractTwoBytes(segment.SourcePort)...)
	result = append(result, extractTwoBytes(segment.DestinationPort)...)
	result = append(result, extractFourBytes(segment.SequenceNumber)...)
	result = append(result, extractFourBytes(segment.AckNumber)...)
	result = append(result, segment.DataOffset<<4)
	result = append(result, segment.Flags)
	result = append(result, extractTwoBytes(segment.WindowSize)...)
	result = append(result, extractTwoBytes(segment.Checksum)...)
	result = append(result, extractTwoBytes(segment.UrgentPtr)...)
	result = append(result, segment.Options...)
	result = append(result, segment.Payload...)

	return result

}

func ParseTCPSegment(tcpBytes []byte, ipPseudoHeaderData *IPPseudoHeaderData, verifyChecksum bool) (*TCPSegment, error) {
	if len(tcpBytes) < 20 {
		return nil, fmt.Errorf("data too short for tcp headers: %d bytes", len(tcpBytes))
	}

	res := &TCPSegment{
		SourcePort:      combineTwoBytes(tcpBytes[0], tcpBytes[1]),
		DestinationPort: combineTwoBytes(tcpBytes[2], tcpBytes[3]),
		SequenceNumber:  combineFourBytes(tcpBytes[4], tcpBytes[5], tcpBytes[6], tcpBytes[7]),
		AckNumber:       combineFourBytes(tcpBytes[8], tcpBytes[9], tcpBytes[10], tcpBytes[11]),
		DataOffset:      tcpBytes[12] >> 4,
		Flags:           tcpBytes[13],
		WindowSize:      combineTwoBytes(tcpBytes[14], tcpBytes[15]),
		Checksum:        combineTwoBytes(tcpBytes[16], tcpBytes[17]),
		UrgentPtr:       combineTwoBytes(tcpBytes[18], tcpBytes[19]),
	}

	headerSizeInBytes := res.DataOffset * 4
	if headerSizeInBytes > 20 {
		res.Options = tcpBytes[20:headerSizeInBytes]
	}
	res.Payload = tcpBytes[headerSizeInBytes:]
	if verifyChecksum && calculateChecksum(tcpBytes, ipPseudoHeaderData) != res.Checksum {
		return nil, fmt.Errorf("checksum does not match, package is dropped")
	}
	return res, nil
}

func combineTwoBytes(byte1 byte, byte2 byte) uint16 {
	return uint16(byte1)<<8 | uint16(byte2)
}

func extractTwoBytes(number uint16) []byte {
	firstByte := byte(number >> 8)
	secondByte := byte(number)
	return []byte{
		firstByte,
		secondByte,
	}
}

func combineFourBytes(byte1 byte, byte2 byte, byte3 byte, byte4 byte) uint32 {
	return uint32(byte1)<<24 | uint32(byte2)<<16 | uint32(byte3)<<8 | uint32(byte4)
}

func extractFourBytes(number uint32) []byte {
	firstByte := byte(number >> 24)
	secondByte := byte(number >> 16)
	thirdByte := byte(number >> 8)
	fourthByte := byte(number)
	return []byte{
		firstByte,
		secondByte,
		thirdByte,
		fourthByte,
	}
}

func calculateChecksum(tcpBytes []byte, pseudoData *IPPseudoHeaderData) uint16 {
	data := createTCPPseudoHeader(tcpBytes, pseudoData)
	if len(data)%2 != 0 {
		data = append(data, 0x00)
	}
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		for sum > 0xFFFF {
			//Handles overflows.
			//That is the reason why uint32 is needed even when the result is uint16
			sum = (sum & 0xFFFF) + sum>>16
		}
	}
	return ^uint16(sum)
}

// In order to calculate the TCP checksum, the TCP headers are extended by some IP Headers to form a PseudoHeader.
func createTCPPseudoHeader(tcpBytes []byte, pseudoData *IPPseudoHeaderData) []byte {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], pseudoData.SourceIP[:])
	copy(pseudoHeader[4:8], pseudoData.DestinationIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = pseudoData.Protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], pseudoData.TotalLength)

	// Create a new slice for the complete pseudo header + TCP segment
	fullPacket := make([]byte, len(pseudoHeader)+len(tcpBytes))
	copy(fullPacket[:12], pseudoHeader)

	// Copy TCP segment with zeroed checksum
	for i := 0; i < len(tcpBytes); i++ {
		if i == 16 || i == 17 {
			fullPacket[12+i] = 0 // Zero out checksum bytes
		} else {
			fullPacket[12+i] = tcpBytes[i]
		}
	}

	return fullPacket
}
