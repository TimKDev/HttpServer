package ipparser

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
