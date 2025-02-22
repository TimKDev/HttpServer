package tcpparser

// TCPHeader represents a TCP segment header.
// It contains all the necessary fields for controlling a TCP connection, including
// sequence numbering, acknowledgment, and control flags for managing the connection state.
type TCPSegment struct {
	// SourcePort specifies the port of the sender.
	SourcePort uint16

	// DestinationPort specifies the port of the receiver.
	DestinationPort uint16

	// SequenceNumber represents the sequence number of the first byte in this segment.
	SequenceNumber uint32

	// AckNumber is used if the ACK flag is set. It acknowledges receipt of all prior bytes.
	AckNumber uint32

	// DataOffset indicates the size of the TCP header in 32-bit words.
	// The top 4 bits represent the header length, and the lower 4 bits are reserved for future use.
	DataOffset uint8

	// Flags is a set of 8 control bits used to manage the state of the connection.
	Flags TCPFlag

	// WindowSize specifies the size of the receive window, which controls the flow of data.
	WindowSize uint16

	// Checksum is used for error-checking the header and data.
	Checksum uint16

	// UrgentPtr is only valid if the URG flag is set. It points to urgent data in the segment.
	UrgentPtr uint16

	Options []byte // Optional field up to 40 bytes
	Payload []byte
}

// TCP flag constants.
// Each flag is represented as a single bit within the Flags field.
type TCPFlag uint8

const (
	// TCPFlagFIN indicates that the sender has finished sending data.
	TCPFlagFIN TCPFlag = 0x01

	// TCPFlagSYN is used to synchronize sequence numbers during connection setup.
	TCPFlagSYN TCPFlag = 0x02

	// TCPFlagRST is used to reset the connection.
	TCPFlagRST TCPFlag = 0x04

	// TCPFlagPSH requests immediate data push to the receiving application.
	TCPFlagPSH TCPFlag = 0x08

	// TCPFlagACK indicates that the Acknowledgment field is significant.
	TCPFlagACK TCPFlag = 0x10

	// TCPFlagURG indicates that the Urgent Pointer field is significant.
	TCPFlagURG TCPFlag = 0x20

	// TCPFlagECE is used for Explicit Congestion Notification (ECN)-echo.
	TCPFlagECE TCPFlag = 0x40

	// TCPFlagCWR indicates that the sender has reduced its congestion window.
	TCPFlagCWR TCPFlag = 0x80
)
