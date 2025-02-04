package ipparser

type IpProtocol byte

// This list is not complete
const (
	ICMP IpProtocol = 0x01
	TCP  IpProtocol = 0x06
	UDP  IpProtocol = 0x0b
	IGMP IpProtocol = 0x02
	IPIP IpProtocol = 0x04
	EGP  IpProtocol = 0x08
	GRE  IpProtocol = 0x2F
	SCTP IpProtocol = 0x84
)
