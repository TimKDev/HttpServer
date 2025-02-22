package iphandler

import (
	"fmt"
	"http-server/helper/slices"
	"http-server/ip-parser"
	"http-server/tcp-handler"
	"http-server/tcp-parser"
	"log"
	"time"
)

type FracmentEntry struct {
	Package     *ipparser.IPPaket
	ArrivalTime time.Time
}

// TODO Dieser Code sollte aus einer Configurations Datei kommen.
var fracmentLifetime = 30 * time.Second

var detectedCongestions [][4]byte
var fracmentedPackages = make(map[string][]FracmentEntry)

// TODO Entferne die direkte Abhängigkeit auf tcp-handler und tcp-parser, indem ein Interface für den TCP Handler definiert wird und dieses Interface in diese Methode reingegeben wird
func HandleIPPackage(ipPackage *ipparser.IPPaket) ([][]byte, error) {
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
			log.Print("Obtained fracment. Rest of the package is not complete.")
			return nil, nil
		}
	}

	if ipPackage.Protocol != ipparser.TCP {
		log.Print("Protocol not supported. Package is dropped.")
		return nil, nil
	}
	//TODO Diese Config muss von außen in diese Funktion hineingegeben werden.
	tcpConfig := tcphandler.TcpHandlerConfig{
		Port:           10000,
		VerifyChecksum: false,
	}
	pseudoHeader := tcpparser.IPPseudoHeaderData{
		SourceIP:      ipPackage.SourceIP,
		DestinationIP: ipPackage.DestinationIP,
		Protocol:      uint8(ipPackage.Protocol),
		TotalLength:   ipPackage.TotalLength,
	}
	resPayload, err := tcphandler.HandleTcpSegment(ipPackage.Payload, &pseudoHeader, tcpConfig)
	if err != nil {
		log.Fatal("Tcp response could not been handled")
	}
	//TODO Hier brachen wir eine Factory Methode, die ein IPPaket in ein RawIPPakete umwandelt und die Lenghts und die Checksum berechnet.
	//Hier müssen dann auch Dinge wie Frakmentierung passieren, falls nötig.
	ipRes := ipparser.IPPaket{
		IpHeaderBytesLength: 20,
		Dscp:                ipparser.AF11,
		Ecn:                 ipparser.AF11,
		TotalLength:         20 + uint16(len(resPayload[0])),
		Identification:      2324,
		DontFracment:        true,
		MoreFracmentsFollow: false,
		FragmentOffset:      0,
		Checksum:            0,
		TimeToLive:          100,
		Protocol:            ipparser.TCP,
		SourceIP:            ipPackage.DestinationIP,
		DestinationIP:       ipPackage.SourceIP,
		Options:             make([]byte, 0),
		Payload:             resPayload[0],
	}

	ipResAsBytes, err := ipparser.ParseIPPaketToBytes(&ipRes)
	if err != nil {
		log.Fatal("Ip package could not been parsed to bytes.")
	}

	res := make([][]byte, 0)
	res = append(res, ipResAsBytes)

	cleanupFracments()

	return res, nil

}

func createFracmentKey(ipPackage *ipparser.IPPaket) string {
	return fmt.Sprintf("%v-%v-%d-%d", ipPackage.DestinationIP, ipPackage.SourceIP, ipPackage.Protocol, ipPackage.Identification)
}

func cleanupFracments() {
	keysToDelete := make([]string, 0)
	for key, entry := range fracmentedPackages {
		validFracments := slices.Where(entry, func(fe FracmentEntry) bool {
			return time.Since(fe.ArrivalTime) <= fracmentLifetime
		})
		if len(validFracments) == 0 {
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
