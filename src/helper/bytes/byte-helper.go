package bytes

func CombineTwoBytes(byte1 byte, byte2 byte) uint16 {
	return uint16(byte1)<<8 | uint16(byte2)
}

func ExtractTwoBytes(number uint16) []byte {
	firstByte := byte(number >> 8)
	secondByte := byte(number)
	return []byte{
		firstByte,
		secondByte,
	}
}

func CombineFourBytes(byte1 byte, byte2 byte, byte3 byte, byte4 byte) uint32 {
	return uint32(byte1)<<24 | uint32(byte2)<<16 | uint32(byte3)<<8 | uint32(byte4)
}

func ExtractFourBytes(number uint32) []byte {
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
