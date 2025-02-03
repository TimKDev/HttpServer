package main

import (
	"fmt"
)

type IpV4Protocol byte

// This list is not complete
const (
	ICMP IpV4Protocol = 0x01
	TCP  IpV4Protocol = 0x06
	UDP  IpV4Protocol = 0x0b
	IGMP IpV4Protocol = 0x02
	IPIP IpV4Protocol = 0x04
	EGP  IpV4Protocol = 0x08
	GRE  IpV4Protocol = 0x2F
	SCTP IpV4Protocol = 0x84
)

type TypeOfService byte

// DSCP (Differentiated Services Code Point) values - first 6 bits
const (
	// Default and Standard Services
	DefaultDSCP TypeOfService = 0x00 // 000000: Default/Best Effort - Regular internet traffic, no special handling
	CS1         TypeOfService = 0x20 // 001000: Class Selector 1 - Low priority background traffic (bulk data, backups)
	CS2         TypeOfService = 0x40 // 010000: Class Selector 2 - OAM (Operations, Administration, and Maintenance)
	CS3         TypeOfService = 0x60 // 011000: Class Selector 3 - Critical applications, business important traffic
	CS4         TypeOfService = 0x80 // 100000: Class Selector 4 - Interactive video, real-time streaming
	CS5         TypeOfService = 0xA0 // 101000: Class Selector 5 - Voice and video signaling (call control)
	CS6         TypeOfService = 0xC0 // 110000: Class Selector 6 - Network control (routing protocols like OSPF, BGP)
	CS7         TypeOfService = 0xE0 // 111000: Class Selector 7 - Network critical traffic, highest priority

	// Assured Forwarding (AF) - Format: AFxy where x=class(1-4), y=drop probability(1-3)
	// Class 1 - Low priority data
	AF11 TypeOfService = 0x28 // 001010: AF11 - Low priority data with low drop probability
	AF12 TypeOfService = 0x30 // 001100: AF12 - Low priority data with medium drop probability
	AF13 TypeOfService = 0x38 // 001110: AF13 - Low priority data with high drop probability

	// Class 2 - Transaction Data
	AF21 TypeOfService = 0x48 // 010010: AF21 - Transaction data with low drop probability
	AF22 TypeOfService = 0x50 // 010100: AF22 - Transaction data with medium drop probability
	AF23 TypeOfService = 0x58 // 010110: AF23 - Transaction data with high drop probability

	// Class 3 - High Priority Data
	AF31 TypeOfService = 0x68 // 011010: AF31 - High priority data with low drop probability (e.g., business apps)
	AF32 TypeOfService = 0x70 // 011100: AF32 - High priority data with medium drop probability
	AF33 TypeOfService = 0x78 // 011110: AF33 - High priority data with high drop probability

	// Class 4 - Streaming Media
	AF41 TypeOfService = 0x88 // 100010: AF41 - Streaming media with low drop probability (e.g., video conferencing)
	AF42 TypeOfService = 0x90 // 100100: AF42 - Streaming media with medium drop probability
	AF43 TypeOfService = 0x98 // 100110: AF43 - Streaming media with high drop probability

	// Expedited Forwarding
	EF TypeOfService = 0xB8 // 101110: Expedited Forwarding - Premium service, lowest latency (VoIP, video calls)
)

// ECN (Explicit Congestion Notification) values - last 2 bits
const (
	NonECT TypeOfService = 0x00 // 00: Non ECN-Capable Transport - No congestion control
	ECT0   TypeOfService = 0x02 // 10: ECN Capable Transport(0) - Supports congestion notification
	ECT1   TypeOfService = 0x01 // 01: ECN Capable Transport(1) - Supports congestion notification (alternate)
	CE     TypeOfService = 0x03 // 11: Congestion Encountered - Network is experiencing congestion
)

type IPPaketV4 struct {
	ipHeaderBytesLength int16         // IHL (Internet Header Length) in bytes
	dscp                TypeOfService //
	ecn                 TypeOfService //
	totalLength         int16         // Total length of packet (header + payload)

	identification      int16 // Used for packet fragmentation
	dontFracment        bool  // Wenn dies gesetzt ist, darf das IP Paket nicht frakmentiert werden, wenn es zu groß ist, wird es gedroppt
	moreFracmentsFollow bool  // Definiert, ob nach diesem Paket noch weitere Pakete folgen könnten.
	fragmentOffset      int16 // 13 bits: Fragment offset in 8-byte units

	timeToLive byte         // TTL: Number of hops before packet is discarded
	protocol   IpV4Protocol // Protocol used in the data portion

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

	if !isChecksumValid(data, headerLength) {
		return nil, fmt.Errorf("header checksum does not match: Package is dropped")
	}

	paket := &IPPaketV4{
		ipHeaderBytesLength: headerLength,
		dscp:                TypeOfService(data[1] & 0xFC),
		ecn:                 TypeOfService(data[1] & 0x03),
		totalLength:         int16(data[2])<<8 | int16(data[3]), //int16(data[2]) hängt 8 Nullen vor das Byte, z.B. 0000 0000 1101 0110. Danach werden diese um 8 nach links verschoben: 1101 0110 0000 0000. Danach kommt ein logisches Oder, d.h. die beiden Bytes data[2] und data[3] werden einfach aneinander gehängt um eine einzelne 16 Bit oder int16 Zahl zu definieren.
		identification:      int16(data[4])<<8 | int16(data[5]),
		dontFracment:        data[6]&0x02 != 0,
		moreFracmentsFollow: data[6]&0x01 != 0,
		fragmentOffset:      int16(data[6]&0x1F)<<8 | int16(data[7]), // Bottom 13 bits
		timeToLive:          data[8],
		protocol:            IpV4Protocol(data[9]),
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

func isChecksumValid(data []byte, headerLength int16) bool {
	var checksum = uint16(data[10])<<8 | uint16(data[11])
	var sum uint32 = 0
	for i := 0; i < int(headerLength); i += 2 {
		if i == 10 { //Skip Checksum
			continue
		}
		if i+1 >= int(headerLength) {
			sum += uint32(data[i]) << 8
			continue
		}
		sum += uint32(data[i])<<8 | uint32(data[i+1])

		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + sum>>16
		}
	}
	res := uint16(sum)

	return checksum == ^res
}
