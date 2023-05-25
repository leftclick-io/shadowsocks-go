package router

import (
	"context"
	"fmt"

	"github.com/database64128/shadowsocks-go/dns"
	"github.com/database64128/shadowsocks-go/domainset"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/prefixset"
	"github.com/database64128/shadowsocks-go/zerocopy"
	"github.com/oschwald/geoip2-golang"
	"go4.org/netipx"
)

// Config is the configuration for a Router.
type Config struct {
	DefaultTCPClientName  string             `json:"defaultTCPClientName"`
	DefaultUDPClientName  string             `json:"defaultUDPClientName"`
	GeoLite2CountryDbPath string             `json:"geoLite2CountryDbPath"`
	DomainSets            []domainset.Config `json:"domainSets"`
	PrefixSets            []prefixset.Config `json:"prefixSets"`
	Routes                []RouteConfig      `json:"routes"`
}

// Router creates a router from the RouterConfig.
func (rc *Config) Router(logger logging.Logger, resolvers []*dns.Resolver, resolverMap map[string]*dns.Resolver, tcpClientMap map[string]zerocopy.TCPClient, udpClientMap map[string]zerocopy.UDPClient, serverIndexByName map[string]int) (*Router, error) {
	defaultRoute := Route{name: "default"}

	switch rc.DefaultTCPClientName {
	case "reject":
	case "":
		if len(tcpClientMap) == 1 {
			for _, tcpClient := range tcpClientMap {
				defaultRoute.tcpClient = tcpClient
			}
		}
	default:
		defaultRoute.tcpClient = tcpClientMap[rc.DefaultTCPClientName]
		if defaultRoute.tcpClient == nil {
			return nil, fmt.Errorf("default TCP client not found: %s", rc.DefaultTCPClientName)
		}
	}

	switch rc.DefaultUDPClientName {
	case "reject":
	case "":
		if len(udpClientMap) == 1 {
			for _, udpClient := range udpClientMap {
				defaultRoute.udpClient = udpClient
			}
		}
	default:
		defaultRoute.udpClient = udpClientMap[rc.DefaultUDPClientName]
		if defaultRoute.udpClient == nil {
			return nil, fmt.Errorf("default UDP client not found: %s", rc.DefaultUDPClientName)
		}
	}

	var (
		geoip *geoip2.Reader
		err   error
	)

	if rc.GeoLite2CountryDbPath != "" {
		geoip, err = geoip2.Open(rc.GeoLite2CountryDbPath)
		if err != nil {
			return nil, err
		}
	}

	domainSetMap := make(map[string]domainset.DomainSet, len(rc.DomainSets))

	for i := range rc.DomainSets {
		domainSet, err := rc.DomainSets[i].DomainSet()
		if err != nil {
			return nil, err
		}
		domainSetMap[rc.DomainSets[i].Name] = domainSet
	}

	prefixSetMap := make(map[string]*netipx.IPSet, len(rc.PrefixSets))

	for i := range rc.PrefixSets {
		s, err := rc.PrefixSets[i].IPSet()
		if err != nil {
			return nil, err
		}
		prefixSetMap[rc.PrefixSets[i].Name] = s
	}

	routes := make([]Route, len(rc.Routes)+1)

	for i := range rc.Routes {
		route, err := rc.Routes[i].Route(geoip, logger, resolvers, resolverMap, tcpClientMap, udpClientMap, serverIndexByName, domainSetMap, prefixSetMap)
		if err != nil {
			return nil, err
		}
		routes[i] = route
	}

	routes[len(rc.Routes)] = defaultRoute

	return &Router{
		geoip:  geoip,
		logger: logger,
		routes: routes,
	}, nil
}

// Router looks up the destination client for requests received by servers.
type Router struct {
	geoip  *geoip2.Reader
	logger logging.Logger
	routes []Route
}

// Close closes the router.
func (r *Router) Close() error {
	if r.geoip != nil {
		return r.geoip.Close()
	}
	return nil
}

// GetTCPClient returns the zerocopy.TCPClient for a TCP request received by server
// from sourceAddrPort to targetAddr.
func (r *Router) GetTCPClient(ctx context.Context, requestInfo RequestInfo) (zerocopy.TCPClient, error) {
	route, err := r.match(ctx, protocolTCP, requestInfo)
	if err != nil {
		return nil, err
	}

	r.logger.Debug("Matched route for TCP connection",
		r.logger.WithField("serverIndex", requestInfo.ServerIndex),
		r.logger.WithField("username", requestInfo.Username),
		r.logger.WithField("sourceAddrPort", requestInfo.SourceAddrPort),
		r.logger.WithField("targetAddress", requestInfo.TargetAddr),
		r.logger.WithField("route", route),
	)

	return route.TCPClient()
}

// GetUDPClient returns the zerocopy.UDPClient for a UDP session received by server.
// The first received packet of the session is from sourceAddrPort to targetAddr.
func (r *Router) GetUDPClient(ctx context.Context, requestInfo RequestInfo) (zerocopy.UDPClient, error) {
	route, err := r.match(ctx, protocolUDP, requestInfo)
	if err != nil {
		return nil, err
	}

	r.logger.Debug("Matched route for UDP session",
		r.logger.WithField("serverIndex", requestInfo.ServerIndex),
		r.logger.WithField("username", requestInfo.Username),
		r.logger.WithField("sourceAddrPort", requestInfo.SourceAddrPort),
		r.logger.WithField("targetAddress", requestInfo.TargetAddr),
		r.logger.WithField("route", route),
	)

	return route.UDPClient()
}

// match returns the matched route for the new TCP request or UDP session.
func (r *Router) match(ctx context.Context, network protocol, requestInfo RequestInfo) (*Route, error) {
	for i := range r.routes {
		matched, err := r.routes[i].Match(ctx, network, requestInfo)
		if err != nil {
			return nil, err
		}
		if matched {
			return &r.routes[i], nil
		}
	}
	panic("did not match default route")
}
