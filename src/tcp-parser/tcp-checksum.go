package tcpparser

import (
	"encoding/binary"
)

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
