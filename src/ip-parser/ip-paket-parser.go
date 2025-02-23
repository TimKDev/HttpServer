package ipparser

import (
	"fmt"
	"http-server/helper/bytes"
)

func ParseIPPaket(data []byte) (*IPPaket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short for IP header: %d bytes", len(data))
	}

	version := (data[0] >> 4) //Dies ist ein Right Shift bei 4 Stellen, z.B. 0100 0101 => 0000 0100, d.h. die ersten 4 Stellen des Bytes werden extrahiert
	if version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}

	headerLength := uint16(data[0]&0x0F) * 4 // Hier wird eine Bitwise Operation mit der Zahl 15 in Dezimal oder 1111 in Binär oder 0x0F in Hexadezimal verwendet, um die letzten 4 Bits zu extrahieren. Ein Left Shift bei 4 würde nicht funktionieren, da dies 0101 0000 ergeben würden und nicht 0000 0101.
	if int(headerLength) > len(data) {
		return nil, fmt.Errorf("header length (%d) exceeds packet size", headerLength)
	}

	if data[6]&0x04 != 0 {
		return nil, fmt.Errorf("invalid ip package: first Bit of IP Flags is not zero")
	}

	if !isChecksumValid(data, headerLength) {
		return nil, fmt.Errorf("header checksum does not match: Package is dropped")
	}

	paket := &IPPaket{
		Dscp:                TypeOfService(data[1] & 0xFC),
		Ecn:                 TypeOfService(data[1] & 0x03),
		TotalLength:         bytes.CombineTwoBytes(data[2], data[3]),
		Identification:      int16(data[4])<<8 | int16(data[5]),
		DontFracment:        data[6]&0x40 != 0,
		MoreFracmentsFollow: data[6]&0x20 != 0,
		FragmentOffset:      uint16(data[6]&0x1F)<<8 | uint16(data[7]), // Bottom 13 bits
		TimeToLive:          data[8],
		Protocol:            IpProtocol(data[9]),
		SourceIP:            [4]byte{data[12], data[13], data[14], data[15]},
		DestinationIP:       [4]byte{data[16], data[17], data[18], data[19]},
		Payload:             data[headerLength:],
	}

	// Handle options if present
	if headerLength > 20 {
		paket.Options = make([]byte, headerLength-20)
		copy(paket.Options, data[20:headerLength])
	}

	if len(data) != int(paket.TotalLength) || paket.TotalLength != headerLength+uint16(len(paket.Options))+uint16(len(paket.Payload)) {
		return nil, fmt.Errorf("inconsistent length definitions in the package, package is dropped")
	}

	return paket, nil
}

func ParseIPPaketToBytes(ipPaket *IPPaket) ([]byte, error) {
	headerLength, totalLength := calculateLengths(ipPaket)
	result := make([]byte, 0, 20)
	result = append(result, byte(4<<4)|byte(headerLength/4))
	result = append(result, byte(ipPaket.Dscp)<<5|byte(ipPaket.Ecn))
	result = append(result, bytes.ExtractTwoBytes(totalLength)...)
	result = append(result, bytes.ExtractTwoBytes(uint16(ipPaket.Identification))...)
	result = append(result, byte(convertBooleanToByte(ipPaket.DontFracment)<<6)|byte(convertBooleanToByte(ipPaket.MoreFracmentsFollow)<<5)|byte(ipPaket.FragmentOffset>>7))
	result = append(result, byte(ipPaket.FragmentOffset))
	result = append(result, ipPaket.TimeToLive)
	result = append(result, byte(ipPaket.Protocol))
	result = append(result, bytes.ExtractTwoBytes(0)...) //Set Checksum to 0
	result = append(result, ipPaket.SourceIP[0])
	result = append(result, ipPaket.SourceIP[1])
	result = append(result, ipPaket.SourceIP[2])
	result = append(result, ipPaket.SourceIP[3])
	result = append(result, ipPaket.DestinationIP[0])
	result = append(result, ipPaket.DestinationIP[1])
	result = append(result, ipPaket.DestinationIP[2])
	result = append(result, ipPaket.DestinationIP[3])
	result = append(result, ipPaket.Payload...)

	checksum := calculateChecksum(result, uint16(headerLength))
	checksumAsBytes := bytes.ExtractTwoBytes(checksum)
	result[10] = checksumAsBytes[0]
	result[11] = checksumAsBytes[1]

	return result, nil
}

func calculateLengths(ipPaket *IPPaket) (uint16, uint16) {
	headerLength := 20 + len(ipPaket.Options)
	totalLength := headerLength + len(ipPaket.Payload)

	return uint16(headerLength), uint16(totalLength)
}

func convertBooleanToByte(boolean bool) byte {
	if boolean {
		return 1
	}
	return 0
}

func isChecksumValid(data []byte, headerLength uint16) bool {
	var checksum = uint16(data[10])<<8 | uint16(data[11])
	return checksum == calculateChecksum(data, headerLength)
}

func calculateChecksum(data []byte, headerLength uint16) uint16 {
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

	return ^res
}
