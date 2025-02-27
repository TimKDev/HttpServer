package receiverworker

import (
	"fmt"
	"os"
)

func dumpPacketToFile(fileName string, data []byte) error {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Write hexdump in Wireshark-compatible format
	for i := 0; i < len(data); i += 16 {
		// Write offset
		fmt.Fprintf(file, "%06x  ", i)

		// Write hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(file, "%02x ", data[i+j])
			} else {
				fmt.Fprintf(file, "   ")
			}
			if j == 7 {
				fmt.Fprintf(file, " ") // Extra space between 8th and 9th byte
			}
		}

		// Write ASCII representation
		fmt.Fprintf(file, " |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 { // Printable ASCII characters
				fmt.Fprintf(file, "%c", b)
			} else {
				fmt.Fprintf(file, ".")
			}
		}
		fmt.Fprintf(file, "|\n")
	}
	return nil
}
