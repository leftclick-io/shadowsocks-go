package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

// sessionQueuedPacket is the structure used by send channels to queue packets for sending.
type sessionQueuedPacket struct {
	buf            []byte
	start          int
	length         int
	targetAddr     conn.Addr
	clientAddrPort netip.AddrPort
}

// sessionClientAddrInfo stores a session's client address information.
type sessionClientAddrInfo struct {
	addrPort netip.AddrPort
	pktinfo  []byte
}

// session keeps track of a UDP session.
type session struct {
	// state synchronizes session initialization and shutdown.
	//
	//  - Swap the natConn in to signal initialization completion.
	//  - Swap the serverConn in to signal shutdown.
	//
	// Callers must check the swapped-out value to determine the next action.
	//
	//  - During initialization, if the swapped-out value is non-nil,
	//    initialization must not proceed.
	//  - During shutdown, if the swapped-out value is nil, preceed to the next entry.
	state                   atomic.Pointer[net.UDPConn]
	clientAddrInfo          atomic.Pointer[sessionClientAddrInfo]
	clientAddrPortCache     netip.AddrPort
	clientPktinfoCache      []byte
	natConnSendCh           chan<- *sessionQueuedPacket
	serverConn              *net.UDPConn
	serverConnUnpacker      zerocopy.ServerUnpacker
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// sessionUplinkGeneric is used for passing information about relay uplink to the relay goroutine.
type sessionUplinkGeneric struct {
	csid                    uint64
	clientName              string
	natConn                 *net.UDPConn
	natConnSendCh           <-chan *sessionQueuedPacket
	natConnPacker           zerocopy.ClientPacker
	natTimeout              time.Duration
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// sessionDownlinkGeneric is used for passing information about relay downlink to the relay goroutine.
type sessionDownlinkGeneric struct {
	csid                    uint64
	clientName              string
	clientAddrInfop         *sessionClientAddrInfo
	clientAddrInfo          *atomic.Pointer[sessionClientAddrInfo]
	natConn                 *net.UDPConn
	natConnRecvBufSize      int
	natConnUnpacker         zerocopy.ClientUnpacker
	serverConn              *net.UDPConn
	serverConnPacker        zerocopy.ServerPacker
	serverConnListenAddress string
	username                string
	listenerIndex           int
}

// UDPSessionRelay is a session-based UDP relay service.
//
// Incoming UDP packets are dispatched to NAT sessions based on the client session ID.
type UDPSessionRelay struct {
	serverName             string
	serverIndex            int
	mtu                    int
	packetBufFrontHeadroom int
	packetBufRecvSize      int
	listeners              []udpRelayServerConn
	server                 zerocopy.UDPSessionServer
	collector              stats.Collector
	router                 *router.Router
	logger                 logging.Logger
	queuedPacketPool       sync.Pool
	wg                     sync.WaitGroup
	mwg                    sync.WaitGroup
	table                  map[uint64]*session
}

func NewUDPSessionRelay(
	serverName string,
	serverIndex, mtu, packetBufFrontHeadroom, packetBufRecvSize, packetBufSize int,
	listeners []udpRelayServerConn,
	server zerocopy.UDPSessionServer,
	collector stats.Collector,
	router *router.Router,
	logger logging.Logger,
) *UDPSessionRelay {
	return &UDPSessionRelay{
		serverName:             serverName,
		serverIndex:            serverIndex,
		mtu:                    mtu,
		packetBufFrontHeadroom: packetBufFrontHeadroom,
		packetBufRecvSize:      packetBufRecvSize,
		listeners:              listeners,
		server:                 server,
		collector:              collector,
		router:                 router,
		logger:                 logger,
		queuedPacketPool: sync.Pool{
			New: func() any {
				return &sessionQueuedPacket{
					buf: make([]byte, packetBufSize),
				}
			},
		},
		table: make(map[uint64]*session),
	}
}

// String implements the Service String method.
func (s *UDPSessionRelay) String() string {
	return "UDP session relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *UDPSessionRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		if err := s.start(ctx, i, &s.listeners[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *UDPSessionRelay) startGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) (err error) {
	lnc.serverConn, err = lnc.listenConfig.ListenUDP(ctx, lnc.network, lnc.address)
	if err != nil {
		return
	}
	lnc.address = lnc.serverConn.LocalAddr().String()

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnGeneric(ctx, index, lnc)
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP session relay service listener",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
	)

	return
}

func (s *UDPSessionRelay) recvFromServerConnGeneric(ctx context.Context, index int, lnc *udpRelayServerConn) {
	cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)

	var (
		n                    int
		cmsgn                int
		flags                int
		err                  error
		packetsReceived      uint64
		payloadBytesReceived uint64
	)

	for {
		queuedPacket := s.getQueuedPacket()
		recvBuf := queuedPacket.buf[s.packetBufFrontHeadroom : s.packetBufFrontHeadroom+s.packetBufRecvSize]

		n, cmsgn, flags, queuedPacket.clientAddrPort, err = lnc.serverConn.ReadMsgUDPAddrPort(recvBuf, cmsgBuf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				s.putQueuedPacket(queuedPacket)
				break
			}

			s.logger.Warn("Failed to read packet from serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read packet from serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		packet := recvBuf[:n]

		csid, err := s.server.SessionInfo(packet)
		if err != nil {
			s.logger.Warn("Failed to extract session info from packet",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		s.server.Lock()

		entry, ok := s.table[csid]
		if !ok {
			entry = &session{
				serverConn:              lnc.serverConn,
				serverConnListenAddress: lnc.address,
				listenerIndex:           index,
			}

			entry.serverConnUnpacker, entry.username, err = s.server.NewUnpacker(packet, csid)
			if err != nil {
				s.logger.Warn("Failed to create unpacker for client session",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
					s.logger.WithField("clientSessionID", csid),
					s.logger.WithField("packetLength", n),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.server.Unlock()
				continue
			}
		}

		queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, queuedPacket.clientAddrPort, s.packetBufFrontHeadroom, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", entry.username),
				s.logger.WithField("clientSessionID", csid),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)

			s.putQueuedPacket(queuedPacket)
			s.server.Unlock()
			continue
		}

		packetsReceived++
		payloadBytesReceived += uint64(queuedPacket.length)

		var clientAddrInfop *sessionClientAddrInfo
		cmsg := cmsgBuf[:cmsgn]

		updateClientAddrPort := entry.clientAddrPortCache != queuedPacket.clientAddrPort
		updateClientPktinfo := !bytes.Equal(entry.clientPktinfoCache, cmsg)

		if updateClientAddrPort {
			entry.clientAddrPortCache = queuedPacket.clientAddrPort
		}

		if updateClientPktinfo {
			entry.clientPktinfoCache = make([]byte, len(cmsg))
			copy(entry.clientPktinfoCache, cmsg)
		}

		if updateClientAddrPort || updateClientPktinfo {
			clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
			if err != nil {
				s.logger.Warn("Failed to parse pktinfo control message from serverConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
					s.logger.WithField("username", entry.username),
					s.logger.WithField("clientSessionID", csid),
					s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)
				s.server.Unlock()
				continue
			}

			clientAddrInfop = &sessionClientAddrInfo{entry.clientAddrPortCache, entry.clientPktinfoCache}
			entry.clientAddrInfo.Store(clientAddrInfop)

			s.logger.Debug("Updated client address info",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", entry.username),
				s.logger.WithField("clientSessionID", csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
				s.logger.WithField("clientPktinfoAddr", clientPktinfoAddr),
				s.logger.WithField("clientPktinfoIfindex", clientPktinfoIfindex),
			)

		}

		if !ok {
			natConnSendCh := make(chan *sessionQueuedPacket, lnc.sendChannelCapacity)
			entry.natConnSendCh = natConnSendCh
			s.table[csid] = entry
			s.wg.Add(1)

			go func() {
				var sendChClean bool

				defer func() {
					s.server.Lock()
					close(natConnSendCh)
					delete(s.table, csid)
					s.server.Unlock()

					if !sendChClean {
						for queuedPacket := range natConnSendCh {
							s.putQueuedPacket(queuedPacket)
						}
					}

					s.wg.Done()
				}()

				c, err := s.router.GetUDPClient(ctx, router.RequestInfo{
					ServerIndex:    s.serverIndex,
					Username:       entry.username,
					SourceAddrPort: queuedPacket.clientAddrPort,
					TargetAddr:     queuedPacket.targetAddr,
				})
				if err != nil {
					s.logger.Warn("Failed to get UDP client for new NAT session",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
						s.logger.WithField("username", entry.username),
						s.logger.WithField("clientSessionID", csid),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithError(err),
					)
					return
				}

				clientInfo, clientSession, err := c.NewSession(ctx)
				if err != nil {
					s.logger.Warn("Failed to create new UDP client session",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
						s.logger.WithField("username", entry.username),
						s.logger.WithField("clientSessionID", csid),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithField("client", clientInfo.Name),
						s.logger.WithError(err),
					)
					return
				}

				natConn, err := clientInfo.ListenConfig.ListenUDP(ctx, "udp", "")
				if err != nil {
					s.logger.Warn("Failed to create UDP socket for new NAT session",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
						s.logger.WithField("username", entry.username),
						s.logger.WithField("clientSessionID", csid),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithField("client", clientInfo.Name),
						s.logger.WithError(err),
					)
					clientSession.Close()
					return
				}

				err = natConn.SetReadDeadline(time.Now().Add(lnc.natTimeout))
				if err != nil {
					s.logger.Warn("Failed to set read deadline on natConn",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
						s.logger.WithField("username", entry.username),
						s.logger.WithField("clientSessionID", csid),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithField("client", clientInfo.Name),
						s.logger.WithField("natTimeout", lnc.natTimeout),
						s.logger.WithError(err),
					)
					natConn.Close()
					clientSession.Close()
					return
				}

				serverConnPacker, err := entry.serverConnUnpacker.NewPacker()
				if err != nil {
					s.logger.Warn("Failed to create packer for client session",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
						s.logger.WithField("username", entry.username),
						s.logger.WithField("clientSessionID", csid),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithError(err),
					)
					natConn.Close()
					clientSession.Close()
					return
				}

				oldState := entry.state.Swap(natConn)
				if oldState != nil {
					natConn.Close()
					clientSession.Close()
					return
				}

				// No more early returns!
				sendChClean = true

				s.logger.Info("UDP session relay started",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
					s.logger.WithField("username", entry.username),
					s.logger.WithField("clientSessionID", csid),
					s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
					s.logger.WithField("client", clientInfo.Name),
				)

				s.wg.Add(1)

				go func() {
					s.relayServerConnToNatConnGeneric(ctx, sessionUplinkGeneric{
						csid:                    csid,
						clientName:              clientInfo.Name,
						natConn:                 natConn,
						natConnSendCh:           natConnSendCh,
						natConnPacker:           clientSession.Packer,
						natTimeout:              lnc.natTimeout,
						serverConnListenAddress: lnc.address,
						username:                entry.username,
						listenerIndex:           index,
					})
					natConn.Close()
					clientSession.Close()
					s.wg.Done()
				}()

				s.relayNatConnToServerConnGeneric(sessionDownlinkGeneric{
					csid:                    csid,
					clientName:              clientInfo.Name,
					clientAddrInfop:         clientAddrInfop,
					clientAddrInfo:          &entry.clientAddrInfo,
					natConn:                 natConn,
					natConnRecvBufSize:      clientSession.MaxPacketSize,
					natConnUnpacker:         clientSession.Unpacker,
					serverConn:              lnc.serverConn,
					serverConnPacker:        serverConnPacker,
					serverConnListenAddress: lnc.address,
					username:                entry.username,
					listenerIndex:           index,
				})
			}()

			s.logger.Debug("New UDP session",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", entry.username),
				s.logger.WithField("clientSessionID", csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
			)
		}

		select {
		case entry.natConnSendCh <- queuedPacket:
		default:
			s.logger.Debug("Dropping packet due to full send channel",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", entry.username),
				s.logger.WithField("clientSessionID", csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
			)

			s.putQueuedPacket(queuedPacket)
		}

		s.server.Unlock()
	}

	s.logger.Info("Finished receiving from serverConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
		s.logger.WithField("packetsReceived", packetsReceived),
		s.logger.WithField("payloadBytesReceived", payloadBytesReceived),
	)
}

func (s *UDPSessionRelay) relayServerConnToNatConnGeneric(ctx context.Context, uplink sessionUplinkGeneric) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		packetsSent      uint64
		payloadBytesSent uint64
	)

	for queuedPacket := range uplink.natConnSendCh {
		destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(ctx, queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", uplink.listenerIndex),
				s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", uplink.username),
				s.logger.WithField("clientSessionID", uplink.csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
				s.logger.WithField("client", uplink.clientName),
				s.logger.WithField("payloadLength", queuedPacket.length),
				s.logger.WithError(err),
			)

			s.putQueuedPacket(queuedPacket)
			continue
		}

		_, err = uplink.natConn.WriteToUDPAddrPort(queuedPacket.buf[packetStart:packetStart+packetLength], destAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", uplink.listenerIndex),
				s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", uplink.username),
				s.logger.WithField("clientSessionID", uplink.csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
				s.logger.WithField("client", uplink.clientName),
				s.logger.WithField("writeDestAddress", destAddrPort),
				s.logger.WithError(err),
			)
		}

		err = uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", uplink.listenerIndex),
				s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
				s.logger.WithField("clientAddress", &queuedPacket.clientAddrPort),
				s.logger.WithField("username", uplink.username),
				s.logger.WithField("clientSessionID", uplink.csid),
				s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
				s.logger.WithField("client", uplink.clientName),
				s.logger.WithField("writeDestAddress", destAddrPort),
				s.logger.WithField("natTimeout", uplink.natTimeout),
				s.logger.WithError(err),
			)
		}

		s.putQueuedPacket(queuedPacket)
		packetsSent++
		payloadBytesSent += uint64(queuedPacket.length)
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", uplink.listenerIndex),
		s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
		s.logger.WithField("username", uplink.username),
		s.logger.WithField("clientSessionID", uplink.csid),
		s.logger.WithField("client", uplink.clientName),
		s.logger.WithField("lastWriteDestAddress", destAddrPort),
		s.logger.WithField("packetsSent", packetsSent),
		s.logger.WithField("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionUplink(uplink.username, packetsSent, payloadBytesSent)
}

func (s *UDPSessionRelay) relayNatConnToServerConnGeneric(downlink sessionDownlinkGeneric) {
	clientAddrInfop := downlink.clientAddrInfop
	clientAddrPort := clientAddrInfop.addrPort
	clientPktinfo := clientAddrInfop.pktinfo
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		packetsSent      uint64
		payloadBytesSent uint64
	)

	packetBuf := make([]byte, headroom.Front+downlink.natConnRecvBufSize+headroom.Rear)
	recvBuf := packetBuf[headroom.Front : headroom.Front+downlink.natConnRecvBufSize]

	for {
		n, _, flags, packetSourceAddrPort, err := downlink.natConn.ReadMsgUDPAddrPort(recvBuf, nil)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to read packet from natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", clientAddrPort),
				s.logger.WithField("username", downlink.username),
				s.logger.WithField("clientSessionID", downlink.csid),
				s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)
			continue
		}
		err = conn.ParseFlagsForError(flags)
		if err != nil {
			s.logger.Warn("Failed to read packet from natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", clientAddrPort),
				s.logger.WithField("username", downlink.username),
				s.logger.WithField("clientSessionID", downlink.csid),
				s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)
			continue
		}

		payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, n)
		if err != nil {
			s.logger.Warn("Failed to unpack packet",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", clientAddrPort),
				s.logger.WithField("username", downlink.username),
				s.logger.WithField("clientSessionID", downlink.csid),
				s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithField("packetLength", n),
				s.logger.WithError(err),
			)
			continue
		}

		if caip := downlink.clientAddrInfo.Load(); caip != clientAddrInfop {
			clientAddrInfop = caip
			clientAddrPort = caip.addrPort
			clientPktinfo = caip.pktinfo
			maxClientPacketSize = zerocopy.MaxPacketSizeForAddr(s.mtu, clientAddrPort.Addr())
		}

		packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
		if err != nil {
			s.logger.Warn("Failed to pack packet",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", clientAddrPort),
				s.logger.WithField("username", downlink.username),
				s.logger.WithField("clientSessionID", downlink.csid),
				s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithField("payloadSourceAddress", payloadSourceAddrPort),
				s.logger.WithField("payloadLength", payloadLength),
				s.logger.WithField("maxClientPacketSize", maxClientPacketSize),
				s.logger.WithError(err),
			)
			continue
		}

		_, _, err = downlink.serverConn.WriteMsgUDPAddrPort(packetBuf[packetStart:packetStart+packetLength], clientPktinfo, clientAddrPort)
		if err != nil {
			s.logger.Warn("Failed to write packet to serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", clientAddrPort),
				s.logger.WithField("username", downlink.username),
				s.logger.WithField("clientSessionID", downlink.csid),
				s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithField("payloadSourceAddress", payloadSourceAddrPort),
				s.logger.WithError(err),
			)
		}

		packetsSent++
		payloadBytesSent += uint64(payloadLength)
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", downlink.listenerIndex),
		s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
		s.logger.WithField("clientAddress", clientAddrPort),
		s.logger.WithField("username", downlink.username),
		s.logger.WithField("clientSessionID", downlink.csid),
		s.logger.WithField("packetsSent", packetsSent),
		s.logger.WithField("payloadBytesSent", payloadBytesSent),
	)

	s.collector.CollectUDPSessionDownlink(downlink.username, packetsSent, payloadBytesSent)
}

// getQueuedPacket retrieves a queued packet from the pool.
func (s *UDPSessionRelay) getQueuedPacket() *sessionQueuedPacket {
	return s.queuedPacketPool.Get().(*sessionQueuedPacket)
}

// putQueuedPacket puts the queued packet back into the pool.
func (s *UDPSessionRelay) putQueuedPacket(queuedPacket *sessionQueuedPacket) {
	s.queuedPacketPool.Put(queuedPacket)
}

// Stop implements the Service Stop method.
func (s *UDPSessionRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			s.logger.Warn("Failed to set read deadline on serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", i),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithError(err),
			)
		}
	}

	// Wait for serverConn receive goroutines to exit,
	// so there won't be any new sessions added to the table.
	s.mwg.Wait()

	s.server.Lock()
	for csid, entry := range s.table {
		natConn := entry.state.Swap(entry.serverConn)
		if natConn == nil {
			continue
		}

		if err := natConn.SetReadDeadline(conn.ALongTimeAgo); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", entry.listenerIndex),
				s.logger.WithField("listenAddress", entry.serverConnListenAddress),
				s.logger.WithField("clientSessionID", csid),
				s.logger.WithError(err),
			)
		}
	}
	s.server.Unlock()

	// Wait for all relay goroutines to exit before closing serverConn,
	// so in-flight packets can be written out.
	s.wg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.serverConn.Close(); err != nil {
			s.logger.Warn("Failed to close serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", i),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithError(err),
			)
		}
	}

	return nil
}
