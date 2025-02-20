package ipparser

import (
	"fmt"
)

func Print(ipPaket *IPPaket) {
	fmt.Println("-------------IP-Paket-------------")
	fmt.Printf("IpHeaderLength: %d bytes\n", ipPaket.IpHeaderBytesLength)
	fmt.Printf("Dscp: %s\n", getDscpName(ipPaket.Dscp))
	fmt.Printf("Ecn: %s\n", getEcnName(ipPaket.Ecn))
	fmt.Printf("TotalLength: %d bytes\n", ipPaket.TotalLength)
	fmt.Printf("Identification: %d\n", ipPaket.Identification)
	fmt.Printf("DontFragment: %t\n", ipPaket.DontFracment)
	fmt.Printf("MoreFragmentsFollow: %t\n", ipPaket.MoreFracmentsFollow)
	fmt.Printf("FragmentOffset: %d\n", ipPaket.FragmentOffset)
	fmt.Printf("TimeToLive: %d\n", ipPaket.TimeToLive)
	fmt.Printf("Protocol: %s\n", getProtocolName(ipPaket.Protocol))
	fmt.Printf("Checksum: %d\n", ipPaket.Checksum)
	fmt.Printf("Source IP: %d.%d.%d.%d\n", ipPaket.SourceIP[0], ipPaket.SourceIP[1], ipPaket.SourceIP[2], ipPaket.SourceIP[3])
	fmt.Printf("Destination IP: %d.%d.%d.%d\n", ipPaket.DestinationIP[0], ipPaket.DestinationIP[1], ipPaket.DestinationIP[2], ipPaket.DestinationIP[3])
	if len(ipPaket.Options) > 0 {
		fmt.Printf("Options Length: %d bytes\n", len(ipPaket.Options))
	}
	fmt.Printf("Payload Length: %d bytes\n", len(ipPaket.Payload))
	fmt.Println("----------------------------------")
}

// Helper function to get protocol name
func getProtocolName(protocol IpProtocol) string {
	switch protocol {
	case ICMP:
		return "ICMP"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case IGMP:
		return "IGMP"
	case IPIP:
		return "IPIP"
	case EGP:
		return "EGP"
	case GRE:
		return "GRE"
	case SCTP:
		return "SCTP"
	default:
		return fmt.Sprintf("Unknown(%d)", protocol)
	}
}

// Helper function to get DSCP name
func getDscpName(dscp TypeOfService) string {
	switch dscp {
	case DefaultDSCP:
		return "Default/Best Effort"
	case CS1:
		return "CS1 (Low Priority)"
	case CS2:
		return "CS2 (OAM)"
	case CS3:
		return "CS3 (Critical Apps)"
	case CS4:
		return "CS4 (Interactive Video)"
	case CS5:
		return "CS5 (Voice/Video Signaling)"
	case CS6:
		return "CS6 (Network Control)"
	case CS7:
		return "CS7 (Network Critical)"
	default:
		return fmt.Sprintf("Unknown(%d)", dscp)
	}
}

// Helper function to get ECN name
func getEcnName(ecn TypeOfService) string {
	switch ecn {
	case NonECT:
		return "Non-ECT (Not ECN-Capable Transport)"
	case ECT0:
		return "ECT(1) (ECN-Capable Transport)"
	case ECT1:
		return "ECT(0) (ECN-Capable Transport)"
	case CE:
		return "CE (Congestion Experienced)"
	default:
		return fmt.Sprintf("Unknown(%d)", ecn)
	}
}
