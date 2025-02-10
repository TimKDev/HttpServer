package tcpparser

import (
	"errors"
	"fmt"
)

func ParseTCPSegment(tcpBytes []byte) (*TCPSegment, error) {
	if len(tcpBytes) < 20 {
		return nil, fmt.Errorf("data too short for tcp headers: %d bytes", len(tcpBytes))
	}

	res := TCPSegment{
		SourcePort:      combineTwoBytes(tcpBytes[0], tcpBytes[1]),
		DestinationPort: combineTwoBytes(tcpBytes[2], tcpBytes[3]),
		SequenceNumber:  ,
		AckNumber:       uint32(tcpBytes[8])<<24 | uint32(tcpBytes[9])<<16 | uint32(tcpBytes[10])<<8 | uint32(tcpBytes[11]),
	}

}

func combineTwoBytes(byte1 byte, byte2 byte) uint16 {
	return uint16(byte1)<<8 | uint16(byte2)
}

func combineFourBytes(byte1 byte, byte2 byte, byte3 byte, byte4 byte) uint32 {
	return uint32(byte1)<<24 | uint32(byte2)<<16 | uint32(byte3)<<8 | uint32(byte4)
}
