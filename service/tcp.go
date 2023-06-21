package service

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/direct"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

const (
	defaultInitialPayloadWaitBufferSize = 1440
	defaultInitialPayloadWaitTimeout    = 250 * time.Millisecond
)

// tcpRelayListener configures the TCP listener for a relay service.
type tcpRelayListener struct {
	listener                     *net.TCPListener
	listenConfig                 conn.ListenConfig
	waitForInitialPayload        bool
	initialPayloadWaitTimeout    time.Duration
	initialPayloadWaitBufferSize int
	network                      string
	address                      string
}

// TCPRelay is a relay service for TCP traffic.
//
// When started, the relay service accepts incoming TCP connections on the server,
// and dispatches them to a client selected by the router.
//
// TCPRelay implements the Service interface.
type TCPRelay struct {
	serverIndex     int
	serverName      string
	listeners       []tcpRelayListener
	acceptWg        sync.WaitGroup
	server          zerocopy.TCPServer
	connCloser      zerocopy.TCPConnCloser
	fallbackAddress conn.Addr
	collector       stats.Collector
	router          *router.Router
	logger          logging.Logger
}

func NewTCPRelay(
	serverIndex int,
	serverName string,
	listeners []tcpRelayListener,
	server zerocopy.TCPServer,
	connCloser zerocopy.TCPConnCloser,
	fallbackAddress conn.Addr,
	collector stats.Collector,
	router *router.Router,
	logger logging.Logger,
) *TCPRelay {
	return &TCPRelay{
		serverIndex:     serverIndex,
		serverName:      serverName,
		listeners:       listeners,
		server:          server,
		connCloser:      connCloser,
		fallbackAddress: fallbackAddress,
		collector:       collector,
		router:          router,
		logger:          logger,
	}
}

// String implements the Service String method.
func (s *TCPRelay) String() string {
	return "TCP relay service for " + s.serverName
}

// Start implements the Service Start method.
func (s *TCPRelay) Start(ctx context.Context) error {
	for i := range s.listeners {
		index := i
		lnc := &s.listeners[index]

		l, err := lnc.listenConfig.ListenTCP(ctx, lnc.network, lnc.address)
		if err != nil {
			return err
		}
		lnc.listener = l
		lnc.address = l.Addr().String()

		s.acceptWg.Add(1)

		go func() {
			for {
				clientConn, err := lnc.listener.AcceptTCP()
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						break
					}
					s.logger.Warn("Failed to accept TCP connection",
						s.logger.WithField("server", s.serverName),
						s.logger.WithField("listener", index),
						s.logger.WithField("listenAddress", lnc.address),
						s.logger.WithError(err),
					)
					continue
				}

				go s.handleConn(ctx, index, lnc, clientConn)
			}

			s.acceptWg.Done()
		}()

		s.logger.Info("Started TCP relay service listener",
			s.logger.WithField("server", s.serverName),
			s.logger.WithField("listener", index),
			s.logger.WithField("listenAddress", lnc.address),
		)
	}
	return nil
}

// handleConn handles an accepted TCP connection.
func (s *TCPRelay) handleConn(ctx context.Context, index int, lnc *tcpRelayListener, clientConn *net.TCPConn) {
	defer clientConn.Close()

	// Get client address.
	clientAddrPort := clientConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	clientAddress := clientAddrPort.String()

	// Handshake.
	clientRW, targetAddr, payload, username, err := s.server.Accept(clientConn)
	if err != nil {
		if err == zerocopy.ErrAcceptDoneNoRelay {
			s.logger.Debug("The accepted connection has been handled without relaying",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
			)
			return
		}

		s.logger.Warn("Failed to complete handshake with client",
			s.logger.WithField("server", s.serverName),
			s.logger.WithField("listener", index),
			s.logger.WithField("listenAddress", lnc.address),
			s.logger.WithField("clientAddress", clientAddress),
			s.logger.WithError(err),
		)

		if !s.fallbackAddress.IsValid() || len(payload) == 0 {
			s.connCloser(clientConn, s.serverName, lnc.address, clientAddress, s.logger)
			return
		}

		clientRW = direct.NewDirectStreamReadWriter(clientConn)
		targetAddr = s.fallbackAddress
	}

	// Convert target address to string once for log messages.
	targetAddress := targetAddr.String()

	// Route.
	c, err := s.router.GetTCPClient(ctx, router.RequestInfo{
		ServerIndex:    s.serverIndex,
		Username:       username,
		SourceAddrPort: clientAddrPort,
		TargetAddr:     targetAddr,
	})
	if err != nil {
		s.logger.Warn("Failed to get TCP client for client connection",
			s.logger.WithField("server", s.serverName),
			s.logger.WithField("listener", index),
			s.logger.WithField("listenAddress", lnc.address),
			s.logger.WithField("clientAddress", clientAddress),
			s.logger.WithField("username", username),
			s.logger.WithField("targetAddress", targetAddress),
			s.logger.WithError(err),
		)
		return
	}

	// Get client info.
	clientInfo := c.Info()

	// Wait for initial payload if all of the following are true:
	// 1. not disabled
	// 2. server does not have native support
	// 3. client has native support
	if lnc.waitForInitialPayload && clientInfo.NativeInitialPayload {
		clientReaderInfo := clientRW.ReaderInfo()
		payloadBufSize := clientReaderInfo.MinPayloadBufferSizePerRead
		if payloadBufSize < lnc.initialPayloadWaitBufferSize {
			payloadBufSize = lnc.initialPayloadWaitBufferSize
		}

		payload = make([]byte, clientReaderInfo.Headroom.Front+payloadBufSize+clientReaderInfo.Headroom.Rear)

		err = clientConn.SetReadDeadline(time.Now().Add(lnc.initialPayloadWaitTimeout))
		if err != nil {
			s.logger.Warn("Failed to set read deadline to initial payload wait timeout",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
				s.logger.WithField("username", username),
				s.logger.WithField("targetAddress", targetAddress),
				s.logger.WithField("client", clientInfo.Name),
				s.logger.WithError(err),
			)
			return
		}

		payloadLength, err := clientRW.ReadZeroCopy(payload, clientReaderInfo.Headroom.Front, payloadBufSize)
		switch {
		case err == nil:
			payload = payload[clientReaderInfo.Headroom.Front : clientReaderInfo.Headroom.Front+payloadLength]
			s.logger.Debug("Got initial payload",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
				s.logger.WithField("username", username),
				s.logger.WithField("targetAddress", targetAddress),
				s.logger.WithField("client", clientInfo.Name),
				s.logger.WithField("payloadLength", payloadLength),
			)

		case errors.Is(err, os.ErrDeadlineExceeded):
			s.logger.Debug("Initial payload wait timed out",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
				s.logger.WithField("username", username),
				s.logger.WithField("targetAddress", targetAddress),
				s.logger.WithField("client", clientInfo.Name),
			)

		default:
			s.logger.Warn("Failed to read initial payload",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
				s.logger.WithField("username", username),
				s.logger.WithField("targetAddress", targetAddress),
				s.logger.WithField("client", clientInfo.Name),
				s.logger.WithError(err),
			)
			return
		}

		err = clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			s.logger.Warn("Failed to reset read deadline",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", index),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithField("clientAddress", clientAddress),
				s.logger.WithField("username", username),
				s.logger.WithField("targetAddress", targetAddress),
				s.logger.WithField("client", clientInfo.Name),
				s.logger.WithError(err),
			)
			return
		}
	}

	// Create remote connection.
	remoteRawRW, remoteRW, err := c.Dial(ctx, targetAddr, payload)
	if err != nil {
		s.logger.Warn("Failed to create remote connection",
			s.logger.WithField("server", s.serverName),
			s.logger.WithField("listener", index),
			s.logger.WithField("listenAddress", lnc.address),
			s.logger.WithField("clientAddress", clientAddress),
			s.logger.WithField("username", username),
			s.logger.WithField("targetAddress", targetAddress),
			s.logger.WithField("client", clientInfo.Name),
			s.logger.WithField("initialPayloadLength", len(payload)),
			s.logger.WithError(err),
		)
		return
	}
	defer remoteRawRW.Close()

	s.logger.Info("Two-way relay started",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
		s.logger.WithField("clientAddress", clientAddress),
		s.logger.WithField("username", username),
		s.logger.WithField("targetAddress", targetAddress),
		s.logger.WithField("client", clientInfo.Name),
		s.logger.WithField("initialPayloadLength", len(payload)),
	)

	// Two-way relay.
	nl2r, nr2l, err := zerocopy.TwoWayRelay(clientRW, remoteRW)
	nl2r += int64(len(payload))
	s.collector.CollectTCPSession(username, uint64(nr2l), uint64(nl2r))
	if err != nil {
		s.logger.Warn("Two-way relay failed",
			s.logger.WithField("server", s.serverName),
			s.logger.WithField("listener", index),
			s.logger.WithField("listenAddress", lnc.address),
			s.logger.WithField("clientAddress", clientAddress),
			s.logger.WithField("username", username),
			s.logger.WithField("targetAddress", targetAddress),
			s.logger.WithField("client", clientInfo.Name),
			s.logger.WithField("nl2r", nl2r),
			s.logger.WithField("nr2l", nr2l),
			s.logger.WithError(err),
		)
		return
	}

	s.logger.Info("Two-way relay completed",
		s.logger.WithField("server", s.serverName),
		s.logger.WithField("listener", index),
		s.logger.WithField("listenAddress", lnc.address),
		s.logger.WithField("clientAddress", clientAddress),
		s.logger.WithField("username", username),
		s.logger.WithField("targetAddress", targetAddress),
		s.logger.WithField("client", clientInfo.Name),
		s.logger.WithField("nl2r", nl2r),
		s.logger.WithField("nr2l", nr2l),
	)
}

// Stop implements the Service Stop method.
func (s *TCPRelay) Stop() error {
	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.SetDeadline(conn.ALongTimeAgo); err != nil {
			s.logger.Warn("Failed to set deadline on listener",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", i),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithError(err),
			)
		}
	}

	s.acceptWg.Wait()

	for i := range s.listeners {
		lnc := &s.listeners[i]
		if err := lnc.listener.Close(); err != nil {
			s.logger.Warn("Failed to close listener",
				s.logger.WithField("server", s.serverName),
				s.logger.WithField("listener", i),
				s.logger.WithField("listenAddress", lnc.address),
				s.logger.WithError(err),
			)
		}
	}

	return nil
}
