package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/database64128/shadowsocks-go/api"
	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/cred"
	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/router"
	"github.com/database64128/shadowsocks-go/stats"
	"github.com/database64128/shadowsocks-go/zerocopy"
)

var errNetworkDisabled = errors.New("this network (tcp or udp) is disabled")

// Relay is a relay service that accepts incoming connections/sessions on a server
// and dispatches them to a client selected by the router.
type Relay interface {
	// String returns the relay service's name.
	String() string

	// Start starts the relay service.
	Start(ctx context.Context) error

	// Stop stops the relay service.
	Stop() error
}

// Config is the main configuration structure.
// It may be marshaled as or unmarshaled from JSON.
type Config struct {
	Servers []ServerConfig       `json:"servers"`
	Clients []ClientConfig       `json:"clients"`
	DNS     []dns.ResolverConfig `json:"dns"`
	Router  router.Config        `json:"router"`
	Stats   stats.Config         `json:"stats"`
	API     api.Config           `json:"api"`
}

// Manager initializes the service manager.
//
// Initialization order: clients -> DNS -> router -> servers
func (sc *Config) Manager(logger logging.Logger) (*Manager, error) {
	if len(sc.Servers) == 0 {
		return nil, errors.New("no services to start")
	}

	if len(sc.Clients) == 0 {
		sc.Clients = []ClientConfig{
			{
				Name:      "direct",
				Protocol:  "direct",
				EnableTCP: true,
				DialerTFO: true,
				EnableUDP: true,
				MTU:       1500,
			},
		}
	}

	listenConfigCache := conn.NewListenConfigCache()
	dialerCache := conn.NewDialerCache()
	tcpClientMap := make(map[string]zerocopy.TCPClient, len(sc.Clients))
	udpClientMap := make(map[string]zerocopy.UDPClient, len(sc.Clients))
	var maxClientPackerHeadroom zerocopy.Headroom

	for i := range sc.Clients {
		clientConfig := &sc.Clients[i]
		clientName := clientConfig.Name
		if err := clientConfig.Initialize(listenConfigCache, dialerCache, logger); err != nil {
			return nil, fmt.Errorf("failed to initialize client %s: %w", clientName, err)
		}

		tcpClient, err := clientConfig.TCPClient()
		switch err {
		case errNetworkDisabled:
		case nil:
			tcpClientMap[clientName] = tcpClient
		default:
			return nil, fmt.Errorf("failed to create TCP client for %s: %w", clientName, err)
		}

		udpClient, err := clientConfig.UDPClient()
		switch err {
		case errNetworkDisabled:
		case nil:
			udpClientMap[clientName] = udpClient
			maxClientPackerHeadroom = zerocopy.MaxHeadroom(maxClientPackerHeadroom, udpClient.Info().PackerHeadroom)
		default:
			return nil, fmt.Errorf("failed to create UDP client for %s: %w", clientName, err)
		}
	}

	resolvers := make([]dns.SimpleResolver, len(sc.DNS))
	resolverMap := make(map[string]dns.SimpleResolver, len(sc.DNS))

	for i := range sc.DNS {
		resolver, err := sc.DNS[i].SimpleResolver(tcpClientMap, udpClientMap, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS resolver %s: %w", sc.DNS[i].Name, err)
		}

		resolvers[i] = resolver
		resolverMap[sc.DNS[i].Name] = resolver
	}

	serverIndexByName := make(map[string]int, len(sc.Servers))

	for i := range sc.Servers {
		serverIndexByName[sc.Servers[i].Name] = i
	}

	router, err := sc.Router.Router(logger, resolvers, resolverMap, tcpClientMap, udpClientMap, serverIndexByName)
	if err != nil {
		return nil, fmt.Errorf("failed to create router: %w", err)
	}

	credman := cred.NewManager(logger)
	apiServer, apiSM, err := sc.API.Server(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create API server: %w", err)
	}

	services := make([]Relay, 0, 2+2*len(sc.Servers))
	services = append(services, credman)
	if apiServer != nil {
		services = append(services, apiServer)
	}

	for i := range sc.Servers {
		serverConfig := &sc.Servers[i]
		collector := sc.Stats.Collector()
		if err := serverConfig.Initialize(listenConfigCache, collector, router, logger, i); err != nil {
			return nil, fmt.Errorf("failed to initialize server %s: %w", serverConfig.Name, err)
		}

		tcpRelay, err := serverConfig.TCPRelay()
		switch err {
		case errNetworkDisabled:
		case nil:
			services = append(services, tcpRelay)
		default:
			return nil, fmt.Errorf("failed to create TCP relay service for %s: %w", serverConfig.Name, err)
		}

		udpRelay, err := serverConfig.UDPRelay(maxClientPackerHeadroom)
		switch err {
		case errNetworkDisabled:
		case nil:
			services = append(services, udpRelay)
		default:
			return nil, fmt.Errorf("failed to create UDP relay service for %s: %w", serverConfig.Name, err)
		}

		if err = serverConfig.PostInit(credman, apiSM); err != nil {
			return nil, fmt.Errorf("failed to post-initialize server %s: %w", serverConfig.Name, err)
		}
	}

	return &Manager{services, router, logger, credman}, nil
}

// Manager manages the services.
type Manager struct {
	services []Relay
	router   *router.Router
	logger   logging.Logger
	credman  *cred.Manager
}

// Start starts all configured services.
func (m *Manager) Start(ctx context.Context) error {
	for _, s := range m.services {
		if err := s.Start(ctx); err != nil {
			return fmt.Errorf("failed to start %s: %w", s.String(), err)
		}
	}
	return nil
}

// GetCredentialManager returns credential manager for given server, if any.
func (m *Manager) GetCredentialManager(name string) (*cred.ManagedServer, bool) {
	return m.credman.GetServer(name)
}

// Stop stops all running services.
func (m *Manager) Stop() {
	for _, s := range m.services {
		if err := s.Stop(); err != nil {
			m.logger.Warn("Failed to stop service",
				m.logger.WithField("service", s),
				m.logger.WithError(err),
			)
		}
		m.logger.Info("Stopped service", m.logger.WithField("service", s))
	}
}

// Close closes the manager.
func (m *Manager) Close() {
	if err := m.router.Close(); err != nil {
		m.logger.Warn("Failed to close router", m.logger.WithError(err))
	}
}
