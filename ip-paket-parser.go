package main

import (
	"fmt"
)

type IPPaketV4 struct {
	ipHeaderBytesLength int16 // IHL (Internet Header Length) in bytes
	typeOfService       byte  // Also known as DSCP + ECN
	totalLength         int16 // Total length of packet (header + payload)

	identification      int16 // Used for packet fragmentation
	dontFracment        bool  // Wenn dies
	moreFracmentsFollow bool
	fragmentOffset      int16 // 13 bits: Fragment offset in 8-byte units

	timeToLive byte // TTL: Number of hops before packet is discarded
	protocol   byte // Protocol used in the data portion

	sourceIP      [4]byte // 32 bits: Source IP address
	destinationIP [4]byte // 32 bits: Destination IP address

	// Optional: Variable length options field (if IHL > 5)
	options []byte // Optional field (only if header length > 20 bytes)
	payload []byte
}

func ParseIPPaketV4(data []byte) (*IPPaketV4, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for IP header: %d bytes", len(data))
	}

	version := (data[0] >> 4) //Dies ist ein Right Shift bei 4 Stellen, z.B. 0100 0101 => 0000 0100, d.h. die ersten 4 Stellen des Bytes werden extrahiert
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	headerLength := int16(data[0]&0x0F) * 4 // Hier wird eine Bitwise Operation mit der Zahl 15 in Dezimal oder 1111 in Binär oder 0x0F in Hexadezimal verwendet, um die letzten 4 Bits zu extrahieren. Ein Left Shift bei 4 würde nicht funktionieren, da dies 0101 0000 ergeben würden und nicht 0000 0101.
	if int(headerLength) > len(data) {
		return nil, fmt.Errorf("header length (%d) exceeds packet size", headerLength)
	}

	if data[6]&0x04 != 0 {
		return nil, fmt.Errorf("invalid ip package: first Bit of IP Flags is not zero")
	}

	if validateChecksum(data, headerLength) {
		return nil, fmt.Errorf("header checksum does not match: Package is dropped")
	}

	paket := &IPPaketV4{
		ipHeaderBytesLength: headerLength,
		typeOfService:       data[1],
		totalLength:         int16(data[2])<<8 | int16(data[3]), //int16(data[2]) hängt 8 Nullen vor das Byte, z.B. 0000 0000 1101 0110. Danach werden diese um 8 nach links verschoben: 1101 0110 0000 0000. Danach kommt ein logisches Oder, d.h. die beiden Bytes data[2] und data[3] werden einfach aneinander gehängt um eine einzelne 16 Bit oder int16 Zahl zu definieren.
		identification:      int16(data[4])<<8 | int16(data[5]),
		dontFracment:        data[6]&0x02 != 0,
		moreFracmentsFollow: data[6]&0x01 != 0,
		fragmentOffset:      int16(data[6]&0x1F)<<8 | int16(data[7]), // Bottom 13 bits
		timeToLive:          data[8],
		protocol:            data[9],
		sourceIP:            [4]byte{data[12], data[13], data[14], data[15]},
		destinationIP:       [4]byte{data[16], data[17], data[18], data[19]},
		payload:             data[headerLength:],
	}

	// Handle options if present
	if headerLength > 20 {
		paket.options = make([]byte, headerLength-20)
		copy(paket.options, data[20:headerLength])
	}

	return paket, nil
}

func validateChecksum(data []byte, headerLength int16) bool {
	var checksum = uint16(data[10])<<8 | uint16(data[11])
	var res uint16 = 0
	for i := 0; i < int(headerLength); i += 2 {
		if i == 10 { //Skip Checksum
			continue
		}
		if i+1 >= int(headerLength) {
			res += uint16(data[i]) << 8
			continue
		}
		res += uint16(data[i])<<8 | uint16(data[i+1])
	}

	return checksum == ^res
}
