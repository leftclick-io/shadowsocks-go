//go:build linux || netbsd

package service

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"golang.org/x/sys/unix"
)

// natUplinkMmsg is used for passing information about relay uplink to the relay goroutine.
type natUplinkMmsg struct {
	clientName              string
	clientAddrPort          netip.AddrPort
	natConn                 *conn.MmsgWConn
	natConnSendCh           <-chan *natQueuedPacket
	natConnPacker           zerocopy.ClientPacker
	natTimeout              time.Duration
	serverConnListenAddress string
	relayBatchSize          int
	listenerIndex           int
}

// natDownlinkMmsg is used for passing information about relay downlink to the relay goroutine.
type natDownlinkMmsg struct {
	clientName              string
	clientAddrPort          netip.AddrPort
	clientPktinfop          *[]byte
	clientPktinfo           *atomic.Pointer[[]byte]
	natConn                 *conn.MmsgRConn
	natConnRecvBufSize      int
	natConnUnpacker         zerocopy.ClientUnpacker
	serverConn              *conn.MmsgWConn
	serverConnPacker        zerocopy.ServerPacker
	serverConnListenAddress string
	relayBatchSize          int
	listenerIndex           int
}

func (s *UDPNATRelay) start(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	switch lnc.batchMode {
	case "sendmmsg", "":
		return s.startMmsg(ctx, index, lnc)
	default:
		return s.startGeneric(ctx, index, lnc)
	}
}

func (s *UDPNATRelay) startMmsg(ctx context.Context, index int, lnc *udpRelayServerConn) error {
	serverConn, err := lnc.listenConfig.ListenUDPRawConn(ctx, lnc.network, lnc.address)
	if err != nil {
		return err
	}
	lnc.serverConn = serverConn.UDPConn
	lnc.address = serverConn.LocalAddr().String()

	s.mwg.Add(1)

	go func() {
		s.recvFromServerConnRecvmmsg(ctx, index, lnc, serverConn.RConn())
		s.mwg.Done()
	}()

	s.logger.Info("Started UDP NAT relay service listener",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
	)

	return nil
}

func (s *UDPNATRelay) recvFromServerConnRecvmmsg(ctx context.Context, index int, lnc *udpRelayServerConn, serverConn *conn.MmsgRConn) {
	n := lnc.serverRecvBatchSize
	qpvec := make([]*natQueuedPacket, n)
	namevec := make([]unix.RawSockaddrInet6, n)
	iovec := make([]unix.Iovec, n)
	cmsgvec := make([][]byte, n)
	msgvec := make([]conn.Mmsghdr, n)

	for i := range msgvec {
		cmsgBuf := make([]byte, conn.SocketControlMessageBufferSize)
		cmsgvec[i] = cmsgBuf
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
		msgvec[i].Msghdr.Control = &cmsgBuf[0]
	}

	var (
		err                  error
		recvmmsgCount        uint64
		packetsReceived      uint64
		payloadBytesReceived uint64
		burstBatchSize       int
	)

	for {
		for i := range iovec[:n] {
			queuedPacket := s.getQueuedPacket()
			qpvec[i] = queuedPacket
			iovec[i].Base = &queuedPacket.buf[s.packetBufFrontHeadroom]
			iovec[i].SetLen(s.packetBufRecvSize)
			msgvec[i].Msghdr.SetControllen(conn.SocketControlMessageBufferSize)
		}

		n, err = serverConn.ReadMsgs(msgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithError(err),
			)

			n = 1
			s.putQueuedPacket(qpvec[0])
			continue
		}

		recvmmsgCount++
		packetsReceived += uint64(n)
		if burstBatchSize < n {
			burstBatchSize = n
		}

		s.mu.Lock()

		msgvecn := msgvec[:n]

		for i := range msgvecn {
			msg := &msgvecn[i]
			queuedPacket := qpvec[i]

			if msg.Msghdr.Controllen == 0 {
				s.logger.Warn("Skipping packet with no control message from serverConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			clientAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from serverConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from serverConn discarded",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", clientAddrPort),
					s.logger.WithField("packetLength", msg.Msglen),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			entry, ok := s.table[clientAddrPort]
			if !ok {
				entry = &natEntry{
					serverConn:              lnc.serverConn,
					serverConnListenAddress: lnc.address,
					listenerIndex:           index,
				}

				entry.serverConnUnpacker, err = s.server.NewUnpacker()
				if err != nil {
					s.logger.Warn("Failed to create unpacker for serverConn",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", clientAddrPort),
						s.logger.WithError(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}
			}

			queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length, err = entry.serverConnUnpacker.UnpackInPlace(queuedPacket.buf, clientAddrPort, s.packetBufFrontHeadroom, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from serverConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", clientAddrPort),
					s.logger.WithField("packetLength", msg.Msglen),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)
				continue
			}

			payloadBytesReceived += uint64(queuedPacket.length)

			var clientPktinfop *[]byte
			cmsg := cmsgvec[i][:msg.Msghdr.Controllen]

			if !bytes.Equal(entry.clientPktinfoCache, cmsg) {
				clientPktinfoAddr, clientPktinfoIfindex, err := conn.ParsePktinfoCmsg(cmsg)
				if err != nil {
					s.logger.Warn("Failed to parse pktinfo control message from serverConn",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", clientAddrPort),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithError(err),
					)

					s.putQueuedPacket(queuedPacket)
					continue
				}

				clientPktinfoCache := make([]byte, len(cmsg))
				copy(clientPktinfoCache, cmsg)
				clientPktinfop = &clientPktinfoCache
				entry.clientPktinfo.Store(clientPktinfop)
				entry.clientPktinfoCache = clientPktinfoCache

				s.logger.Debug("Updated client pktinfo",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", clientAddrPort),
					s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
					s.logger.WithField("clientPktinfoAddr", clientPktinfoAddr),
					s.logger.WithField("clientPktinfoIfindex", clientPktinfoIfindex),
				)
			}

			if !ok {
				natConnSendCh := make(chan *natQueuedPacket, lnc.sendChannelCapacity)
				entry.natConnSendCh = natConnSendCh
				s.table[clientAddrPort] = entry
				s.wg.Add(1)

				go func() {
					var sendChClean bool

					defer func() {
						s.mu.Lock()
						close(natConnSendCh)
						delete(s.table, clientAddrPort)
						s.mu.Unlock()

						if !sendChClean {
							for queuedPacket := range natConnSendCh {
								s.putQueuedPacket(queuedPacket)
							}
						}

						s.wg.Done()
					}()

					c, err := s.router.GetUDPClient(ctx, router.RequestInfo{
						ServerIndex:    s.serverIndex,
						SourceAddrPort: clientAddrPort,
						TargetAddr:     queuedPacket.targetAddr,
					})
					if err != nil {
						s.logger.Warn("Failed to get UDP client for new NAT session",
							s.logger.WithField("server", s.serverName),
							s.logger.WithField("listener", index),
							s.logger.WithField("listenAddress", lnc.address),
							s.logger.WithField("clientAddress", clientAddrPort),
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
							s.logger.WithField("clientAddress", clientAddrPort),
							s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
							s.logger.WithField("client", clientInfo.Name),
							s.logger.WithError(err),
						)
						return
					}

					natConn, err := clientInfo.ListenConfig.ListenUDPRawConn(ctx, "udp", "")
					if err != nil {
						s.logger.Warn("Failed to create UDP socket for new NAT session",
							s.logger.WithField("server", s.serverName),
							s.logger.WithField("listener", index),
							s.logger.WithField("listenAddress", lnc.address),
							s.logger.WithField("clientAddress", clientAddrPort),
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
							s.logger.WithField("clientAddress", clientAddrPort),
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
						s.logger.Warn("Failed to create packer for serverConn",
							s.logger.WithField("server", s.serverName),
							s.logger.WithField("listener", index),
							s.logger.WithField("listenAddress", lnc.address),
							s.logger.WithField("clientAddress", clientAddrPort),
							s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
							s.logger.WithError(err),
						)
						natConn.Close()
						clientSession.Close()
						return
					}

					oldState := entry.state.Swap(natConn.UDPConn)
					if oldState != nil {
						natConn.Close()
						clientSession.Close()
						return
					}

					// No more early returns!
					sendChClean = true

					s.logger.Info("UDP NAT relay started",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithField("clientAddress", clientAddrPort),
						s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
						s.logger.WithField("client", clientInfo.Name),
					)

					s.wg.Add(1)

					go func() {
						s.relayServerConnToNatConnSendmmsg(ctx, natUplinkMmsg{
							clientName:              clientInfo.Name,
							clientAddrPort:          clientAddrPort,
							natConn:                 natConn.WConn(),
							natConnSendCh:           natConnSendCh,
							natConnPacker:           clientSession.Packer,
							natTimeout:              lnc.natTimeout,
							serverConnListenAddress: lnc.address,
							relayBatchSize:          lnc.relayBatchSize,
							listenerIndex:           index,
						})
						natConn.Close()
						clientSession.Close()
						s.wg.Done()
					}()

					s.relayNatConnToServerConnSendmmsg(natDownlinkMmsg{
						clientName:              clientInfo.Name,
						clientAddrPort:          clientAddrPort,
						clientPktinfop:          clientPktinfop,
						clientPktinfo:           &entry.clientPktinfo,
						natConn:                 natConn.RConn(),
						natConnRecvBufSize:      clientSession.MaxPacketSize,
						natConnUnpacker:         clientSession.Unpacker,
						serverConn:              serverConn.WConn(),
						serverConnPacker:        serverConnPacker,
						serverConnListenAddress: lnc.address,
						relayBatchSize:          lnc.relayBatchSize,
						listenerIndex:           index,
					})
				}()

				s.logger.Debug("New UDP NAT session",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", index),
					s.logger.WithField("listenAddress", lnc.address),
					s.logger.WithField("clientAddress", clientAddrPort),
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
					s.logger.WithField("clientAddress", clientAddrPort),
					s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
				)

				s.putQueuedPacket(queuedPacket)
			}
		}

		s.mu.Unlock()
	}

	for i := range qpvec {
		s.putQueuedPacket(qpvec[i])
	}

	s.logger.Info("Finished receiving from serverConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
		s.logger.WithField("recvmmsgCount", recvmmsgCount),
		s.logger.WithField("packetsReceived", packetsReceived),
		s.logger.WithField("payloadBytesReceived", payloadBytesReceived),
		s.logger.WithField("burstBatchSize", burstBatchSize),
	)
}

func (s *UDPNATRelay) relayServerConnToNatConnSendmmsg(ctx context.Context, uplink natUplinkMmsg) {
	var (
		destAddrPort     netip.AddrPort
		packetStart      int
		packetLength     int
		err              error
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	qpvec := make([]*natQueuedPacket, uplink.relayBatchSize)
	namevec := make([]unix.RawSockaddrInet6, uplink.relayBatchSize)
	iovec := make([]unix.Iovec, uplink.relayBatchSize)
	msgvec := make([]conn.Mmsghdr, uplink.relayBatchSize)

	for i := range msgvec {
		msgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&namevec[i]))
		msgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		msgvec[i].Msghdr.Iov = &iovec[i]
		msgvec[i].Msghdr.SetIovlen(1)
	}

main:
	for {
		var count int

		// Block on first dequeue op.
		queuedPacket, ok := <-uplink.natConnSendCh
		if !ok {
			break
		}

	dequeue:
		for {
			destAddrPort, packetStart, packetLength, err = uplink.natConnPacker.PackInPlace(ctx, queuedPacket.buf, queuedPacket.targetAddr, queuedPacket.start, queuedPacket.length)
			if err != nil {
				s.logger.Warn("Failed to pack packet for natConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", uplink.listenerIndex),
					s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
					s.logger.WithField("clientAddress", uplink.clientAddrPort),
					s.logger.WithField("targetAddress", &queuedPacket.targetAddr),
					s.logger.WithField("client", uplink.clientName),
					s.logger.WithField("payloadLength", queuedPacket.length),
					s.logger.WithError(err),
				)

				s.putQueuedPacket(queuedPacket)

				if count == 0 {
					continue main
				}
				goto next
			}

			qpvec[count] = queuedPacket
			namevec[count] = conn.AddrPortToSockaddrInet6(destAddrPort)
			iovec[count].Base = &queuedPacket.buf[packetStart]
			iovec[count].SetLen(packetLength)
			count++
			payloadBytesSent += uint64(queuedPacket.length)

			if count == uplink.relayBatchSize {
				break
			}

		next:
			select {
			case queuedPacket, ok = <-uplink.natConnSendCh:
				if !ok {
					break dequeue
				}
			default:
				break dequeue
			}
		}

		if err := uplink.natConn.WriteMsgs(msgvec[:count], 0); err != nil {
			s.logger.Warn("Failed to batch write packets to natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", uplink.listenerIndex),
				s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
				s.logger.WithField("clientAddress", uplink.clientAddrPort),
				s.logger.WithField("lastTargetAddress", &qpvec[count-1].targetAddr),
				s.logger.WithField("client", uplink.clientName),
				s.logger.WithField("lastWriteDestAddress", destAddrPort),
				s.logger.WithError(err),
			)
		}

		if err := uplink.natConn.SetReadDeadline(time.Now().Add(uplink.natTimeout)); err != nil {
			s.logger.Warn("Failed to set read deadline on natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", uplink.listenerIndex),
				s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
				s.logger.WithField("clientAddress", uplink.clientAddrPort),
				s.logger.WithField("lastTargetAddress", &qpvec[count-1].targetAddr),
				s.logger.WithField("client", uplink.clientName),
				s.logger.WithField("lastWriteDestAddress", destAddrPort),
				s.logger.WithField("natTimeout", uplink.natTimeout),
				s.logger.WithError(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(count)
		if burstBatchSize < count {
			burstBatchSize = count
		}

		qpvecn := qpvec[:count]

		for i := range qpvecn {
			s.putQueuedPacket(qpvecn[i])
		}

		if !ok {
			break
		}
	}

	s.logger.Info("Finished relay serverConn -> natConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", uplink.listenerIndex),
		s.logger.WithField("listenAddress", uplink.serverConnListenAddress),
		s.logger.WithField("clientAddress", uplink.clientAddrPort),
		s.logger.WithField("client", uplink.clientName),
		s.logger.WithField("lastWriteDestAddress", destAddrPort),
		s.logger.WithField("sendmmsgCount", sendmmsgCount),
		s.logger.WithField("packetsSent", packetsSent),
		s.logger.WithField("payloadBytesSent", payloadBytesSent),
		s.logger.WithField("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionUplink("", uplink.clientAddrPort.Addr().String(), packetsSent, payloadBytesSent)
}

func (s *UDPNATRelay) relayNatConnToServerConnSendmmsg(downlink natDownlinkMmsg) {
	clientPktinfop := downlink.clientPktinfop
	clientPktinfo := *clientPktinfop
	maxClientPacketSize := zerocopy.MaxPacketSizeForAddr(s.mtu, downlink.clientAddrPort.Addr())

	serverConnPackerInfo := downlink.serverConnPacker.ServerPackerInfo()
	natConnUnpackerInfo := downlink.natConnUnpacker.ClientUnpackerInfo()
	headroom := zerocopy.UDPRelayHeadroom(serverConnPackerInfo.Headroom, natConnUnpackerInfo.Headroom)

	var (
		sendmmsgCount    uint64
		packetsSent      uint64
		payloadBytesSent uint64
		burstBatchSize   int
	)

	name, namelen := conn.AddrPortToSockaddr(downlink.clientAddrPort)
	savec := make([]unix.RawSockaddrInet6, downlink.relayBatchSize)
	bufvec := make([][]byte, downlink.relayBatchSize)
	riovec := make([]unix.Iovec, downlink.relayBatchSize)
	siovec := make([]unix.Iovec, downlink.relayBatchSize)
	rmsgvec := make([]conn.Mmsghdr, downlink.relayBatchSize)
	smsgvec := make([]conn.Mmsghdr, downlink.relayBatchSize)

	for i := 0; i < downlink.relayBatchSize; i++ {
		packetBuf := make([]byte, headroom.Front+downlink.natConnRecvBufSize+headroom.Rear)
		bufvec[i] = packetBuf

		riovec[i].Base = &packetBuf[headroom.Front]
		riovec[i].SetLen(downlink.natConnRecvBufSize)

		rmsgvec[i].Msghdr.Name = (*byte)(unsafe.Pointer(&savec[i]))
		rmsgvec[i].Msghdr.Namelen = unix.SizeofSockaddrInet6
		rmsgvec[i].Msghdr.Iov = &riovec[i]
		rmsgvec[i].Msghdr.SetIovlen(1)

		smsgvec[i].Msghdr.Name = name
		smsgvec[i].Msghdr.Namelen = namelen
		smsgvec[i].Msghdr.Iov = &siovec[i]
		smsgvec[i].Msghdr.SetIovlen(1)
		smsgvec[i].Msghdr.Control = &clientPktinfo[0]
		smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
	}

	for {
		nr, err := downlink.natConn.ReadMsgs(rmsgvec, 0)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}

			s.logger.Warn("Failed to batch read packets from natConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", downlink.clientAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithError(err),
			)
			continue
		}

		var ns int
		rmsgvecn := rmsgvec[:nr]

		for i := range rmsgvecn {
			msg := &rmsgvecn[i]

			packetSourceAddrPort, err := conn.SockaddrToAddrPort(msg.Msghdr.Name, msg.Msghdr.Namelen)
			if err != nil {
				s.logger.Warn("Failed to parse sockaddr of packet from natConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", downlink.listenerIndex),
					s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
					s.logger.WithField("clientAddress", downlink.clientAddrPort),
					s.logger.WithField("client", downlink.clientName),
					s.logger.WithError(err),
				)
				continue
			}

			err = conn.ParseFlagsForError(int(msg.Msghdr.Flags))
			if err != nil {
				s.logger.Warn("Packet from natConn discarded",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", downlink.listenerIndex),
					s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
					s.logger.WithField("clientAddress", downlink.clientAddrPort),
					s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
					s.logger.WithField("client", downlink.clientName),
					s.logger.WithField("packetLength", msg.Msglen),
					s.logger.WithError(err),
				)
				continue
			}

			packetBuf := bufvec[i]

			payloadSourceAddrPort, payloadStart, payloadLength, err := downlink.natConnUnpacker.UnpackInPlace(packetBuf, packetSourceAddrPort, headroom.Front, int(msg.Msglen))
			if err != nil {
				s.logger.Warn("Failed to unpack packet from natConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", downlink.listenerIndex),
					s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
					s.logger.WithField("clientAddress", downlink.clientAddrPort),
					s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
					s.logger.WithField("client", downlink.clientName),
					s.logger.WithField("packetLength", msg.Msglen),
					s.logger.WithError(err),
				)
				continue
			}

			packetStart, packetLength, err := downlink.serverConnPacker.PackInPlace(packetBuf, payloadSourceAddrPort, payloadStart, payloadLength, maxClientPacketSize)
			if err != nil {
				s.logger.Warn("Failed to pack packet for serverConn",
					s.logger.WithField("server", s.serverName),
					s.logger.WithField("listener", downlink.listenerIndex),
					s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
					s.logger.WithField("clientAddress", downlink.clientAddrPort),
					s.logger.WithField("packetSourceAddress", packetSourceAddrPort),
					s.logger.WithField("client", downlink.clientName),
					s.logger.WithField("payloadSourceAddress", payloadSourceAddrPort),
					s.logger.WithField("payloadLength", payloadLength),
					s.logger.WithField("maxClientPacketSize", maxClientPacketSize),
					s.logger.WithError(err),
				)
				continue
			}

			siovec[ns].Base = &packetBuf[packetStart]
			siovec[ns].SetLen(packetLength)
			ns++
			payloadBytesSent += uint64(payloadLength)
		}

		if ns == 0 {
			continue
		}

		if cpp := downlink.clientPktinfo.Load(); cpp != clientPktinfop {
			clientPktinfo = *cpp
			clientPktinfop = cpp

			for i := range smsgvec {
				smsgvec[i].Msghdr.Control = &clientPktinfo[0]
				smsgvec[i].Msghdr.SetControllen(len(clientPktinfo))
			}
		}

		err = downlink.serverConn.WriteMsgs(smsgvec[:ns], 0)
		if err != nil {
			s.logger.Warn("Failed to batch write packets to serverConn",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", downlink.listenerIndex),
				s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
				s.logger.WithField("clientAddress", downlink.clientAddrPort),
				s.logger.WithField("client", downlink.clientName),
				s.logger.WithError(err),
			)
		}

		sendmmsgCount++
		packetsSent += uint64(ns)
		if burstBatchSize < ns {
			burstBatchSize = ns
		}
	}

	s.logger.Info("Finished relay serverConn <- natConn",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", downlink.listenerIndex),
		s.logger.WithField("listenAddress", downlink.serverConnListenAddress),
		s.logger.WithField("clientAddress", downlink.clientAddrPort),
		s.logger.WithField("client", downlink.clientName),
		s.logger.WithField("sendmmsgCount", sendmmsgCount),
		s.logger.WithField("packetsSent", packetsSent),
		s.logger.WithField("payloadBytesSent", payloadBytesSent),
		s.logger.WithField("burstBatchSize", burstBatchSize),
	)

	s.collector.CollectUDPSessionDownlink("", downlink.clientAddrPort.Addr().String(), packetsSent, payloadBytesSent)
}
