package tcpparser

import (
	"fmt"
)

func PrintTcpSegment(tcpSegment *TCPSegment) {
	// Print basic header information
	fmt.Printf("TCP Segment:\n")
	fmt.Printf("  Source Port: %d\n", tcpSegment.SourcePort)
	fmt.Printf("  Destination Port: %d\n", tcpSegment.DestinationPort)
	fmt.Printf("  Sequence Number: %d\n", tcpSegment.SequenceNumber)
	fmt.Printf("  Acknowledgment Number: %d\n", tcpSegment.AckNumber)

	// Print flags
	fmt.Printf("  Flags:")
	if tcpSegment.Flags&TCPFlag(TCPFlagFIN) != 0 {
		fmt.Printf(" FIN")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagSYN) != 0 {
		fmt.Printf(" SYN")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagRST) != 0 {
		fmt.Printf(" RST")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagPSH) != 0 {
		fmt.Printf(" PSH")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagACK) != 0 {
		fmt.Printf(" ACK")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagURG) != 0 {
		fmt.Printf(" URG")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagECE) != 0 {
		fmt.Printf(" ECE")
	}
	if tcpSegment.Flags&TCPFlag(TCPFlagCWR) != 0 {
		fmt.Printf(" CWR")
	}
	fmt.Printf("\n")

	// Print other fields
	fmt.Printf("  Window Size: %d\n", tcpSegment.WindowSize)

	// Print urgent pointer if URG flag is set
	if tcpSegment.Flags&TCPFlag(TCPFlagURG) != 0 {
		fmt.Printf("  Urgent Pointer: %d\n", tcpSegment.UrgentPtr)
	}

	// Print options length if present
	if len(tcpSegment.Options) > 0 {
		fmt.Printf("  Options Length: %d bytes\n", len(tcpSegment.Options))
	}

	// Print payload length if present
	if len(tcpSegment.Payload) > 0 {
		fmt.Printf("  Payload Length: %d bytes\n", len(tcpSegment.Payload))
	}
}
