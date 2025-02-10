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

func ParseTCPSegment(tcpBytes []byte, ipPseudoHeaderData *IPPseudoHeaderData) (*TCPSegment, error) {
	if len(tcpBytes) < 20 {
		return nil, fmt.Errorf("data too short for tcp headers: %d bytes", len(tcpBytes))
	}

	res := &TCPSegment{
		SourcePort:      combineTwoBytes(tcpBytes[0], tcpBytes[1]),
		DestinationPort: combineTwoBytes(tcpBytes[2], tcpBytes[3]),
		SequenceNumber:  combineFourBytes(tcpBytes[4], tcpBytes[5], tcpBytes[6], tcpBytes[7]),
		AckNumber:       combineFourBytes(tcpBytes[8], tcpBytes[9], tcpBytes[10], tcpBytes[11]),
		DataOffset:      tcpBytes[12] & 0xF0,
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
	if calculateChecksum(tcpBytes, ipPseudoHeaderData) != res.Checksum {
		return nil, fmt.Errorf("checksum does not match, package is dropped")
	}
	return res, nil
}

func combineTwoBytes(byte1 byte, byte2 byte) uint16 {
	return uint16(byte1)<<8 | uint16(byte2)
}

func combineFourBytes(byte1 byte, byte2 byte, byte3 byte, byte4 byte) uint32 {
	return uint32(byte1)<<24 | uint32(byte2)<<16 | uint32(byte3)<<8 | uint32(byte4)
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
	for i := 0; i < len(tcpBytes); i++ {
		if i == 16 || i == 17 {
			//Remove Checksum
			continue
		}
		pseudoHeader = append(pseudoHeader, tcpBytes[i])
	}

	return pseudoHeader
}
