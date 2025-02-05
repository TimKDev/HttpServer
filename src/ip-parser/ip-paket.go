package ipparser

type IPPaket struct {
	IpHeaderBytesLength int16         // IHL (Internet Header Length) in bytes
	Dscp                TypeOfService //
	Ecn                 TypeOfService //
	TotalLength         int16         // Total length of packet (header + payload)

	Identification      int16 // Dies ist eine eindeutige Zahl die definiert welche Frakmente zusammengehören, wenn von einer Quelle mehrere unterschiedliche IP Pakete frakmentiert werden
	DontFracment        bool  // Wenn dies gesetzt ist, darf das IP Paket nicht frakmentiert werden, wenn es zu groß ist, wird es gedroppt
	MoreFracmentsFollow bool  // Definiert, ob nach diesem Paket noch weitere Pakete folgen könnten.
	FragmentOffset      int16 // 13 bits: Fragment offset in 8-byte units

	TimeToLive byte       // TTL: Number of hops before packet is discarded
	Protocol   IpProtocol // Protocol used in the data portion

	SourceIP      [4]byte // 32 bits: Source IP address
	DestinationIP [4]byte // 32 bits: Destination IP address

	// Optional: Variable length options field (if IHL > 5)
	Options []byte // Optional field (only if header length > 20 bytes)
	Payload []byte
}
