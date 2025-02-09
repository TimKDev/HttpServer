package iphandler

import (
	"errors"
	"http-server/helper/slices"
	"http-server/ip-parser"
	"log"
)

func buildPackageFromFracments(fracmentedPackages map[string][]FracmentEntry) *ipparser.IPPaket {
	for _, fracmentParts := range fracmentedPackages {
		if isPackageComplete(fracmentParts) {
			combinedPackage, err := combineFracments(fracmentParts)
			if err != nil {
				//Handle Error
				log.Fatal("Combining Fracments failed", err)
			}
			return combinedPackage
		}
	}
	return nil
}

func combineFracments(fracmentParts []FracmentEntry) (*ipparser.IPPaket, error) {
	// Fracments are combined by taking the headers of the first package fracment and combining the payloads of the other packages
	var firstPackage *ipparser.IPPaket
	var totalSizePayload uint16
	for _, fracment := range fracmentParts {
		if fracment.Package.FragmentOffset == 0 {
			firstPackage = fracment.Package
		}
		totalSizePayload += uint16(fracment.Package.TotalLength) - uint16(fracment.Package.IpHeaderBytesLength)
	}

	if firstPackage == nil {
		return nil, errors.New("first fracment is missing")
	}

	combinedPayload := make([]byte, totalSizePayload)
	for _, fracment := range fracmentParts {
		offset := int(fracment.Package.FragmentOffset * 8)
		for i, val := range fracment.Package.Payload {
			combinedPayload[offset+i] = val
		}
	}

	res := &ipparser.IPPaket{
		IpHeaderBytesLength: firstPackage.IpHeaderBytesLength,
		Dscp:                firstPackage.Dscp,
		Ecn:                 firstPackage.Ecn,
		TotalLength:         firstPackage.IpHeaderBytesLength + int16(totalSizePayload),
		Identification:      firstPackage.Identification,
		DontFracment:        firstPackage.DontFracment,
		MoreFracmentsFollow: false,
		FragmentOffset:      0,
		TimeToLive:          firstPackage.TimeToLive,
		Protocol:            firstPackage.Protocol,
		SourceIP:            firstPackage.SourceIP,
		DestinationIP:       firstPackage.DestinationIP,
		Options:             firstPackage.Options,
		Payload:             combinedPayload,
	}

	return res, nil
}

func isPackageComplete(fracmentParts []FracmentEntry) bool {
	neededOffsets := make([]uint16, len(fracmentParts))
	neededOffsets = append(neededOffsets, 0)
	containsLastFracment := false
	for _, fracmentEntry := range fracmentParts {
		fracment := fracmentEntry.Package
		if !fracment.MoreFracmentsFollow {
			containsLastFracment = true
			continue
		}
		offset := uint16(fracment.FragmentOffset * 8)
		fracmentLength := uint16(fracment.TotalLength) - uint16(fracment.IpHeaderBytesLength)
		neededOffsets = append(neededOffsets, offset+fracmentLength)
	}
	if !containsLastFracment {
		return false
	}

	for _, fracment := range fracmentParts {
		if !slices.Contains(neededOffsets, uint16(fracment.Package.FragmentOffset*8)) {
			return false
		}
	}
	return true
}