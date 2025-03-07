package tcpreceiver

import (
	"fmt"
	tcpparser "http-server/tcp-parser"
	tcpsender "http-server/tcp-sender"
	"log"
	"slices"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

type TcpDataSegments struct {
	SequenceNumber uint32
	Payload        []byte
}

type TcpSessionStatus int

const (
	WaitingForHandShake   TcpSessionStatus = 0
	ConnectionEstablished TcpSessionStatus = 1
)

type TcpSession struct {
	DestinationIP          [4]byte
	DestinationPort        uint16
	ReceivedSegments       []TcpDataSegments
	SendedSegments         []TcpDataSegments
	LastSendAck            uint32
	LastSendSequenceNumber uint32
	State                  TcpSessionStatus
	ClientWindowSize       uint16
	ServerWindowSize       uint16
}

var sessions = make([]*TcpSession, 0)

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) error {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil
	}

	fmt.Println("Received TCP Package:")
	tcpparser.PrintTcpSegment(tcpSegment)

	//Syn => Erstellt eine neue TCP Session und schickt ein SYNACK
	if tcpSegment.Flags == tcpparser.TCPFlagSYN {
		handleSYN(*tcpSegment, ipPseudoHeaderData, config)
	}

	return nil
}

func handleSYN(tcpSegment tcpparser.TCPSegment, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) {
	//serverSequenceNum := rand.Uint32()
	serverSequenceNum := uint32(1)
	serverWindowSize := uint16(65535) // Use a standard window size

	newSession := TcpSession{
		DestinationIP:          ipPseudoHeaderData.SourceIP,
		DestinationPort:        tcpSegment.SourcePort,
		ClientWindowSize:       tcpSegment.WindowSize,
		ServerWindowSize:       serverWindowSize,
		ReceivedSegments:       make([]TcpDataSegments, 0),
		SendedSegments:         make([]TcpDataSegments, 0),
		LastSendSequenceNumber: serverSequenceNum,
		LastSendAck:            tcpSegment.SequenceNumber + 1,
		State:                  WaitingForHandShake,
	}

	err := AddSession(&newSession)

	if err != nil {
		log.Print("An active session still exists and needs to be terminated before a new one can start.")
		return
	}

	synAckRes := tcpparser.TCPSegment{
		SourcePort:      uint16(config.Port),
		DestinationPort: tcpSegment.SourcePort,
		SequenceNumber:  serverSequenceNum,
		AckNumber:       tcpSegment.SequenceNumber + 1,
		Flags:           tcpparser.TCPFlagSYN | tcpparser.TCPFlagACK,
		WindowSize:      serverWindowSize,
		UrgentPtr:       0,
		Options:         tcpSegment.Options, // Copy options from request
		Payload:         make([]byte, 0),
	}

	tcpsender.SendTCPSegment(ipPseudoHeaderData.DestinationIP, ipPseudoHeaderData.SourceIP, &synAckRes)
}

func handleACK(tcpSegment tcpparser.TCPSegment, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) {

}

func AddSession(session *TcpSession) error {
	exists := slices.ContainsFunc(sessions, func(s *TcpSession) bool {
		return CompareSessions(session, s)
	})

	if exists {
		return fmt.Errorf("session already exists")
	}

	sessions = append(sessions, session)
	return nil
}

func CompareSessions(session1 *TcpSession, session2 *TcpSession) bool {
	if session1.DestinationPort != session2.DestinationPort {
		return false
	}
	for i, _ := range session1.DestinationIP {
		if session1.DestinationIP[i] != session2.DestinationIP[i] {
			return false
		}
	}

	return true
}
