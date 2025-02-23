package tcpparser

type IPPseudoHeaderData struct {
	SourceIP      [4]byte
	DestinationIP [4]byte
	Protocol      uint8
	TotalLength   uint16 //Total Length des TCP Pakets (TCP Header + Payload) => Nicht die Gesamtlänge des IP Pakets!
}
