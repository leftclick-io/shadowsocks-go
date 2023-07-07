package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/cmp"
	"github.com/database64128/shadowsocks-go/slices"
)

type metadataCollector struct {
	lastSessionTimestamp     atomic.Uint64
	lastSessionClientAddress atomic.Pointer[string]
}

type trafficCollector struct {
	downlinkPackets atomic.Uint64
	downlinkBytes   atomic.Uint64
	uplinkPackets   atomic.Uint64
	uplinkBytes     atomic.Uint64
	tcpSessions     atomic.Uint64
	udpSessions     atomic.Uint64
}

func getTimestamp() uint64 {
	return uint64(time.Now().Unix())
}

func (mc *metadataCollector) collectSessionMetadata(clientAddress string) {
	if mc == nil {
		return
	}

	// Update last session timestamp.
	mc.lastSessionTimestamp.Store(getTimestamp())

	// Store client address if it is not empty.
	if clientAddress != "" {
		mc.lastSessionClientAddress.Store(&clientAddress)
	}
}

func (mc *metadataCollector) snapshot() (m Metadata) {
	m.LastSessionTimestamp = mc.lastSessionTimestamp.Load()

	if a := mc.lastSessionClientAddress.Load(); a != nil {
		m.LastSessionClientAddress = *a
	}

	return m
}

func (mc *metadataCollector) snapshotAndReset() (m Metadata) {
	m.LastSessionTimestamp = mc.lastSessionTimestamp.Swap(0)

	if a := mc.lastSessionClientAddress.Swap(nil); a != nil {
		m.LastSessionClientAddress = *a
	}

	return m
}

func (tc *trafficCollector) collectTCPSession(downlinkBytes, uplinkBytes uint64) {
	tc.downlinkBytes.Add(downlinkBytes)
	tc.uplinkBytes.Add(uplinkBytes)
	tc.tcpSessions.Add(1)
}

func (tc *trafficCollector) collectUDPSessionDownlink(downlinkPackets, downlinkBytes uint64) {
	tc.downlinkPackets.Add(downlinkPackets)
	tc.downlinkBytes.Add(downlinkBytes)
	tc.udpSessions.Add(1)
}

func (tc *trafficCollector) collectUDPSessionUplink(uplinkPackets, uplinkBytes uint64) {
	tc.uplinkPackets.Add(uplinkPackets)
	tc.uplinkBytes.Add(uplinkBytes)
}

type Metadata struct {
	LastSessionTimestamp     uint64 `json:"lastSessionTimestamp"`
	LastSessionClientAddress string `json:"lastSessionClientAddress"`
}

// Traffic stores the traffic statistics.
type Traffic struct {
	DownlinkPackets uint64 `json:"downlinkPackets"`
	DownlinkBytes   uint64 `json:"downlinkBytes"`
	UplinkPackets   uint64 `json:"uplinkPackets"`
	UplinkBytes     uint64 `json:"uplinkBytes"`
	TCPSessions     uint64 `json:"tcpSessions"`
	UDPSessions     uint64 `json:"udpSessions"`
}

func (t *Traffic) Add(u Traffic) {
	t.DownlinkPackets += u.DownlinkPackets
	t.DownlinkBytes += u.DownlinkBytes
	t.UplinkPackets += u.UplinkPackets
	t.UplinkBytes += u.UplinkBytes
	t.TCPSessions += u.TCPSessions
	t.UDPSessions += u.UDPSessions
}

func (tc *trafficCollector) snapshot() Traffic {
	return Traffic{
		DownlinkPackets: tc.downlinkPackets.Load(),
		DownlinkBytes:   tc.downlinkBytes.Load(),
		UplinkPackets:   tc.uplinkPackets.Load(),
		UplinkBytes:     tc.uplinkBytes.Load(),
		TCPSessions:     tc.tcpSessions.Load(),
		UDPSessions:     tc.udpSessions.Load(),
	}
}

func (tc *trafficCollector) snapshotAndReset() Traffic {
	return Traffic{
		DownlinkPackets: tc.downlinkPackets.Swap(0),
		DownlinkBytes:   tc.downlinkBytes.Swap(0),
		UplinkPackets:   tc.uplinkPackets.Swap(0),
		UplinkBytes:     tc.uplinkBytes.Swap(0),
		TCPSessions:     tc.tcpSessions.Swap(0),
		UDPSessions:     tc.udpSessions.Swap(0),
	}
}

type userCollector struct {
	trafficCollector
	metadataCollector
}

// User stores the user's traffic statistics.
type User struct {
	Name string `json:"username"`
	Traffic
	Metadata
}

// Compare is useful for sorting users by name.
func (u User) Compare(other User) int {
	return cmp.Compare(u.Name, other.Name)
}

func (uc *userCollector) snapshot(username string) User {
	return User{
		Name:     username,
		Traffic:  uc.trafficCollector.snapshot(),
		Metadata: uc.metadataCollector.snapshot(),
	}
}

func (uc *userCollector) snapshotAndReset(username string) User {
	return User{
		Name:     username,
		Traffic:  uc.trafficCollector.snapshotAndReset(),
		Metadata: uc.metadataCollector.snapshotAndReset(),
	}
}

type serverCollector struct {
	tc  trafficCollector
	ucs map[string]*userCollector
	mu  sync.RWMutex
}

// NewServerCollector returns a new collector for collecting server traffic statistics.
func NewServerCollector() *serverCollector {
	return &serverCollector{
		ucs: make(map[string]*userCollector),
	}
}

func (sc *serverCollector) userCollector(username string) *userCollector {
	sc.mu.RLock()
	uc := sc.ucs[username]
	sc.mu.RUnlock()
	if uc == nil {
		sc.mu.Lock()
		uc = sc.ucs[username]
		if uc == nil {
			uc = &userCollector{}
			sc.ucs[username] = uc
		}
		sc.mu.Unlock()
	}
	return uc
}

func (sc *serverCollector) collectors(username string) (*trafficCollector, *metadataCollector) {
	if username == "" {
		return &sc.tc, nil
	}

	uc := sc.userCollector(username)
	return &uc.trafficCollector, &uc.metadataCollector
}

// CollectTCPSession implements the Collector CollectTCPSession method.
func (sc *serverCollector) CollectTCPSession(username, remoteAddress string, downlinkBytes, uplinkBytes uint64) {
	tr, mt := sc.collectors(username)
	tr.collectTCPSession(downlinkBytes, uplinkBytes)
	mt.collectSessionMetadata(remoteAddress)
}

// CollectUDPSessionDownlink implements the Collector CollectUDPSessionDownlink method.
func (sc *serverCollector) CollectUDPSessionDownlink(username, remoteAddress string, downlinkPackets, downlinkBytes uint64) {
	tr, mt := sc.collectors(username)
	tr.collectUDPSessionDownlink(downlinkPackets, downlinkBytes)
	mt.collectSessionMetadata(remoteAddress)
}

// CollectUDPSessionUplink implements the Collector CollectUDPSessionUplink method.
func (sc *serverCollector) CollectUDPSessionUplink(username, remoteAddress string, uplinkPackets, uplinkBytes uint64) {
	tr, mt := sc.collectors(username)
	tr.collectUDPSessionUplink(uplinkPackets, uplinkBytes)
	mt.collectSessionMetadata(remoteAddress)
}

// Server stores the server's traffic statistics.
type Server struct {
	Traffic
	Users []User `json:"users,omitempty"`
}

// Snapshot implements the Collector Snapshot method.
func (sc *serverCollector) Snapshot() (s Server) {
	s.Traffic = sc.tc.snapshot()
	sc.mu.RLock()
	s.Users = make([]User, 0, len(sc.ucs))
	for username, uc := range sc.ucs {
		u := uc.snapshot(username)
		s.Traffic.Add(u.Traffic)
		s.Users = append(s.Users, u)
	}
	sc.mu.RUnlock()
	slices.SortFunc(s.Users, User.Compare)
	return
}

// SnapshotAndReset implements the Collector SnapshotAndReset method.
func (sc *serverCollector) SnapshotAndReset() (s Server) {
	s.Traffic = sc.tc.snapshotAndReset()
	sc.mu.RLock()
	s.Users = make([]User, 0, len(sc.ucs))
	for username, uc := range sc.ucs {
		u := uc.snapshotAndReset(username)
		s.Traffic.Add(u.Traffic)
		s.Users = append(s.Users, u)
	}
	sc.mu.RUnlock()
	slices.SortFunc(s.Users, User.Compare)
	return
}

// Collector collects server traffic statistics.
type Collector interface {
	// CollectTCPSession collects the TCP session's traffic statistics.
	CollectTCPSession(username, remoteAddress string, downlinkBytes, uplinkBytes uint64)

	// CollectUDPSessionDownlink collects the UDP session's downlink traffic statistics.
	CollectUDPSessionDownlink(username, remoteAddress string, downlinkPackets, downlinkBytes uint64)

	// CollectUDPSessionUplink collects the UDP session's uplink traffic statistics.
	CollectUDPSessionUplink(username, remoteAddress string, uplinkPackets, uplinkBytes uint64)

	// Snapshot returns the server's traffic statistics.
	Snapshot() Server

	// SnapshotAndReset returns the server's traffic statistics and resets the statistics.
	SnapshotAndReset() Server
}

// NoopCollector is a no-op collector.
// Its collect methods do nothing and its snapshot method returns empty statistics.
type NoopCollector struct{}

// CollectTCPSession implements the Collector CollectTCPSession method.
func (NoopCollector) CollectTCPSession(username, remoteAddress string, downlinkBytes, uplinkBytes uint64) {
}

// CollectUDPSessionDownlink implements the Collector CollectUDPSessionDownlink method.
func (NoopCollector) CollectUDPSessionDownlink(username, remoteAddress string, downlinkPackets, downlinkBytes uint64) {
}

// CollectUDPSessionUplink implements the Collector CollectUDPSessionUplink method.
func (NoopCollector) CollectUDPSessionUplink(username, remoteAddress string, uplinkPackets, uplinkBytes uint64) {
}

// Snapshot implements the Collector Snapshot method.
func (NoopCollector) Snapshot() Server {
	return Server{}
}

// SnapshotAndReset implements the Collector SnapshotAndReset method.
func (NoopCollector) SnapshotAndReset() Server {
	return Server{}
}

// Config stores configuration for the stats collector.
type Config struct {
	Enabled bool `json:"enabled"`
}

// Collector returns a new stats collector from the config.
func (c Config) Collector() Collector {
	if c.Enabled {
		return NewServerCollector()
	}
	return NoopCollector{}
}
