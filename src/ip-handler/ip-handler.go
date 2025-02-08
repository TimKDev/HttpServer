package iphandler

import (
	"http-server/helper/slices"
	"http-server/ip-parser"
	"http-server/tcp-handler"
	"log"
)

var detectedCongestions [][4]byte

// TODO Some sort of lifetime for orphaned package cleanup is needed.
var fracmentedPackages []*ipparser.IPPaket

func HandleIPPackage(ipPackage *ipparser.IPPaket) {
	if ipPackage.Ecn == ipparser.CE {
		if !slices.ContainsFunc(detectedCongestions, ipPackage.SourceIP, compareIPs) {
			detectedCongestions = append(detectedCongestions, ipPackage.SourceIP)
		}
	}
	if ipPackage.MoreFracmentsFollow || ipPackage.FragmentOffset != 0 {
		fracmentedPackages = append(fracmentedPackages, ipPackage)
		ipPackage = buildPackageFromFracments(fracmentedPackages)
	}

	if ipPackage == nil {
		return
	}

	if ipPackage.Protocol != ipparser.TCP {
		log.Print("Protocol not supported. Package is dropped.")
		return
	}
	tcphandler.HandleTcpPackage(ipPackage.Payload)
}

func compareIPs(ip1 [4]byte, ip2 [4]byte) bool {
	for i := 0; i < 4; i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}
