package tcpparser

import (
	"fmt"
	"http-server/helper/bytes"
)

func ParseTCPSegment(tcpBytes []byte, ipPseudoHeaderData *IPPseudoHeaderData, verifyChecksum bool) (*TCPSegment, error) {
	if len(tcpBytes) < 20 {
		return nil, fmt.Errorf("data too short for tcp headers: %d bytes", len(tcpBytes))
	}

	dataOffset := tcpBytes[12] >> 4
	checksum := bytes.CombineTwoBytes(tcpBytes[16], tcpBytes[17])

	res := &TCPSegment{
		SourcePort:      bytes.CombineTwoBytes(tcpBytes[0], tcpBytes[1]),
		DestinationPort: bytes.CombineTwoBytes(tcpBytes[2], tcpBytes[3]),
		SequenceNumber:  bytes.CombineFourBytes(tcpBytes[4], tcpBytes[5], tcpBytes[6], tcpBytes[7]),
		AckNumber:       bytes.CombineFourBytes(tcpBytes[8], tcpBytes[9], tcpBytes[10], tcpBytes[11]),
		Flags:           TCPFlag(tcpBytes[13]),
		WindowSize:      bytes.CombineTwoBytes(tcpBytes[14], tcpBytes[15]),
		UrgentPtr:       bytes.CombineTwoBytes(tcpBytes[18], tcpBytes[19]),
	}

	headerSizeInBytes := dataOffset * 4
	if headerSizeInBytes > 20 {
		res.Options = tcpBytes[20:headerSizeInBytes]
	}
	res.Payload = tcpBytes[headerSizeInBytes:]
	if verifyChecksum && calculateChecksum(tcpBytes, ipPseudoHeaderData) != checksum {
		return nil, fmt.Errorf("checksum does not match, package is dropped")
	}
	return res, nil
}
