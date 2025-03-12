package tcpreceiver

import (
	"fmt"
	"http-server/http-receiver"
	"http-server/tcp-parser"
	"http-server/tcp-sender"
	"log"
	"math/rand/v2"
	"slices"
)

type TcpHandlerConfig struct {
	Port           uint
	VerifyChecksum bool
}

var sessions = make([]*tcpsender.TcpSession, 0)

func HandleTcpSegment(tcpPackage []byte, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) error {
	tcpSegment, err := tcpparser.ParseTCPSegment(tcpPackage, ipPseudoHeaderData, config.VerifyChecksum)
	if err != nil {
		return err
	}
	if tcpSegment.DestinationPort != uint16(config.Port) {
		return nil
	}

	if isFlagSet(tcpSegment.Flags, tcpparser.TCPFlagSYN) {
		handleSYN(*tcpSegment, ipPseudoHeaderData, config)
	}
	if isFlagSet(tcpSegment.Flags, tcpparser.TCPFlagACK) {
		handleACK(*tcpSegment, ipPseudoHeaderData, config)
		handleSessions()
	}

	return nil
}

func handleSessions() {
	for _, session := range sessions {
		closeConnectionAfterHttpResponse(session)

		slices.SortFunc(session.ReceivedSegments, func(a tcpsender.ReceivedTcpDataSegment, b tcpsender.ReceivedTcpDataSegment) int {
			return int(b.SequenceNumber) - int(a.SequenceNumber)
		})

		resBody := make([]byte, 0)
		isIncomplete := false
		for i, data := range session.ReceivedSegments {
			if i != 0 {
				prevData := session.ReceivedSegments[i-1]
				if prevData.SequenceNumber+uint32(len(prevData.Payload)) != data.SequenceNumber {
					isIncomplete = true
					break
				}
			}
			resBody = append(resBody, data.Payload...)
		}

		if isIncomplete || session.IsHandledByBackend {
			continue
		}

		if len(session.ReceivedSegments) != 0 {
			//TODO This only works when only one TCP Segment with data is send to the server!
			session.IsHandledByBackend = true
		}

		go httpreceiver.HandleHttpRequest(session, resBody)
	}
}

func isFlagSet(bitEnum tcpparser.TCPFlag, flag tcpparser.TCPFlag) bool {
	return bitEnum&flag == flag
}

func handleSYN(tcpSegment tcpparser.TCPSegment, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) {
	serverSequenceNum := rand.Uint32()
	serverWindowSize := uint16(65535) // Use a standard window size

	newSession := tcpsender.TcpSession{
		SourceIP:           ipPseudoHeaderData.DestinationIP,
		DestinationIP:      ipPseudoHeaderData.SourceIP,
		SourcePort:         tcpSegment.DestinationPort,
		DestinationPort:    tcpSegment.SourcePort,
		ClientWindowSize:   tcpSegment.WindowSize,
		ServerWindowSize:   serverWindowSize,
		ReceivedSegments:   make([]tcpsender.ReceivedTcpDataSegment, 0),
		SendedSegments:     make([]tcpsender.SendedTcpDataSegment, 0),
		NextSequenceNumber: serverSequenceNum + 1,
		LastSendAck:        tcpSegment.SequenceNumber + 1,
		State:              tcpsender.WaitingForHandShake,
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
		Options:         make([]byte, 0),
		Payload:         make([]byte, 0),
	}

	tcpsender.SendTCPSegment(ipPseudoHeaderData.DestinationIP, ipPseudoHeaderData.SourceIP, &synAckRes)
}

func handleACK(tcpSegment tcpparser.TCPSegment, ipPseudoHeaderData *tcpparser.IPPseudoHeaderData, config TcpHandlerConfig) {
	session := FindSession(ipPseudoHeaderData.SourceIP, tcpSegment.SourcePort)
	if session == nil {
		//Here it should be signaled to the client, that the SYN segment is missing.
		return
	}

	session.State = tcpsender.ConnectionEstablished
	ackDataSendFromServer(session, tcpSegment.AckNumber)

	if len(tcpSegment.Payload) != 0 {
		handleDataSendToServer(session, &tcpSegment, config)
	}
}

func handleDataSendToServer(session *tcpsender.TcpSession, tcpSegment *tcpparser.TCPSegment, config TcpHandlerConfig) {
	session.ReceivedSegments = append(session.ReceivedSegments, tcpsender.ReceivedTcpDataSegment{
		SequenceNumber: tcpSegment.SequenceNumber,
		Payload:        tcpSegment.Payload,
	})

	currentAck := getCurrentAckNum(session)

	ackRes := tcpparser.TCPSegment{

		SourcePort:      uint16(config.Port),
		DestinationPort: tcpSegment.SourcePort,
		SequenceNumber:  session.NextSequenceNumber,
		AckNumber:       currentAck,
		Flags:           tcpparser.TCPFlagACK,
		WindowSize:      session.ServerWindowSize,
		UrgentPtr:       0,
		Options:         make([]byte, 0),
		Payload:         make([]byte, 0),
	}

	session.LastSendAck = currentAck

	tcpsender.SendTCPSegment(session.SourceIP, session.DestinationIP, &ackRes)
}

func ackDataSendFromServer(session *tcpsender.TcpSession, receivedAckNumber uint32) {
	for i := range session.SendedSegments {
		data := &session.SendedSegments[i]
		if data.SequenceNumber+uint32(len(data.Payload)) <= receivedAckNumber {
			data.IsAcknowledged = true
		}
	}
}

func closeConnectionAfterHttpResponse(session *tcpsender.TcpSession) {
	//TODO This only works for a simple Http Request with Response and without Keep Alive
	if len(session.SendedSegments) == 0 {
		return
	}
	for _, sendedData := range session.SendedSegments {
		if !sendedData.IsAcknowledged {
			return
		}
	}

	finSegment := tcpparser.TCPSegment{
		SourcePort:      session.SourcePort,
		DestinationPort: session.DestinationPort,
		SequenceNumber:  session.NextSequenceNumber,
		AckNumber:       session.LastSendAck,
		Flags:           tcpparser.TCPFlagFIN | tcpparser.TCPFlagACK,
		WindowSize:      session.ServerWindowSize,
		UrgentPtr:       0,
		Options:         make([]byte, 0),
		Payload:         make([]byte, 0),
	}

	tcpsender.SendTCPSegment(session.SourceIP, session.DestinationIP, &finSegment)
	removeSession(session)
}

func removeSession(session *tcpsender.TcpSession) {
	for i, s := range sessions {
		if CompareSessions(s, session) {
			sessions = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}
}

func getCurrentAckNum(session *tcpsender.TcpSession) uint32 {
	ackNumRes := session.LastSendAck
	for _, data := range session.ReceivedSegments {
		dataAckNum := data.SequenceNumber + uint32(len(data.Payload))
		if dataAckNum < ackNumRes {
			continue
		}
		ackNumRes = dataAckNum
	}
	return ackNumRes
}

func FindSession(destinationIP [4]byte, destinationPort uint16) *tcpsender.TcpSession {
	idx := slices.IndexFunc(sessions, func(s *tcpsender.TcpSession) bool {
		return s.DestinationPort == destinationPort &&
			slices.Equal(s.DestinationIP[:], destinationIP[:])
	})

	if idx == -1 {
		return nil
	}
	return sessions[idx]
}

func AddSession(session *tcpsender.TcpSession) error {
	exists := slices.ContainsFunc(sessions, func(s *tcpsender.TcpSession) bool {
		return CompareSessions(session, s)
	})

	if exists {
		return fmt.Errorf("session already exists")
	}

	sessions = append(sessions, session)
	return nil
}

func CompareSessions(session1 *tcpsender.TcpSession, session2 *tcpsender.TcpSession) bool {
	if session1.DestinationPort != session2.DestinationPort {
		return false
	}
	for i := range session1.DestinationIP {
		if session1.DestinationIP[i] != session2.DestinationIP[i] {
			return false
		}
	}

	return true
}
