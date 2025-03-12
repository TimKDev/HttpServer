package ipsender

import (
	"http-server/ip-parser"
	"http-server/sender-worker"
)

func SendIPPackage(sourceIP [4]byte, destinationIP [4]byte, destinationPort uint16, payload []byte) error {
	ipPackage := ipparser.IPPaket{
		Dscp:                ipparser.DefaultDSCP,
		Ecn:                 ipparser.NonECT,
		TotalLength:         uint16(20 + len(payload)),
		Identification:      2324,
		DontFracment:        true,
		MoreFracmentsFollow: false,
		FragmentOffset:      0,
		TimeToLive:          100,
		Protocol:            ipparser.TCP,
		SourceIP:            sourceIP,
		DestinationIP:       destinationIP,
		Options:             make([]byte, 0),
		Payload:             payload,
	}

	ipPackageAsBytes, err := ipparser.ParseIPPaketToBytes(&ipPackage)
	if err != nil {
		return err
	}

	msg := senderworker.SenderMessage{
		DestinationIP:   destinationIP,
		DestinationPort: destinationPort,
		IPPaket:         ipPackageAsBytes,
	}

	senderworker.Send(&msg, nil)

	return nil
}
