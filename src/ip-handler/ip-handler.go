package iphandler

import (
	"fmt"
	"http-server/helper/slices"
	"http-server/ip-parser"
	"http-server/tcp-handler"
	"log"
	"time"
)

type FracmentEntry struct {
	Package     *ipparser.IPPaket
	ArrivalTime time.Time
}

var fracmentLifetime = 30 * time.Second

var detectedCongestions [][4]byte
var fracmentedPackages = make(map[string][]FracmentEntry)

func HandleIPPackage(ipPackage *ipparser.IPPaket) {
	if ipPackage.Ecn == ipparser.CE {
		if !slices.ContainsFunc(detectedCongestions, ipPackage.SourceIP, compareIPs) {
			detectedCongestions = append(detectedCongestions, ipPackage.SourceIP)
		}
	}
	if ipPackage.MoreFracmentsFollow || ipPackage.FragmentOffset != 0 {
		key := createFracmentKey(ipPackage)
		fracmentedPackages[key] = append(fracmentedPackages[key], FracmentEntry{
			Package:     ipPackage,
			ArrivalTime: time.Now(),
		})
		ipPackage = buildPackageFromFracments(fracmentedPackages)

		if ipPackage != nil {
			delete(fracmentedPackages, key)
		} else {
			return
		}
	}

	if ipPackage.Protocol != ipparser.TCP {
		log.Print("Protocol not supported. Package is dropped.")
		return
	}
	tcphandler.HandleTcpPackage(ipPackage.Payload)
	cleanupFracments()

}

func createFracmentKey(ipPackage *ipparser.IPPaket) string {
	return fmt.Sprintf("%v-%v-%d-%d", ipPackage.DestinationIP, ipPackage.SourceIP, ipPackage.Protocol, ipPackage.Identification)
}

func cleanupFracments() {
	keysToDelete := make([]string, 2)
	for key, entry := range fracmentedPackages {
		entry = slices.Where(entry, func(fe FracmentEntry) bool {
			return time.Since(fe.ArrivalTime) <= fracmentLifetime
		})
		if len(entry) == 0 {
			keysToDelete = append(keysToDelete, key)
		}
	}
	for _, key := range keysToDelete {
		delete(fracmentedPackages, key)
	}
}

func compareIPs(ip1 [4]byte, ip2 [4]byte) bool {
	for i := 0; i < 4; i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}
