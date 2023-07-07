package stats

import "testing"

const (
	AlexAddress  = "127.0.0.1"
	SteveAddress = "127.0.0.2"
)

func collect(t *testing.T, c Collector) {
	t.Helper()
	c.CollectTCPSession("Steve", SteveAddress, 1024, 2048)
	c.CollectUDPSessionUplink("Alex", AlexAddress, 1, 3072)
	c.CollectUDPSessionDownlink("Steve", SteveAddress, 2, 4096)
	c.CollectTCPSession("Alex", AlexAddress, 5120, 6144)
	c.CollectUDPSessionDownlink("Alex", AlexAddress, 4, 7168)
	c.CollectUDPSessionUplink("Steve", "", 8, 8192)
	c.CollectTCPSession("Steve", SteveAddress, 9216, 10240)
	c.CollectUDPSessionDownlink("Alex", AlexAddress, 16, 11264)
	c.CollectUDPSessionDownlink("Steve", SteveAddress, 32, 12288)
	c.CollectUDPSessionDownlink("Alex", AlexAddress, 64, 13312)
	c.CollectUDPSessionUplink("Steve", SteveAddress, 128, 14336)
	c.CollectUDPSessionUplink("Alex", AlexAddress, 256, 15360)
	c.CollectUDPSessionUplink("Alex", AlexAddress, 512, 16384)
	c.CollectTCPSession("Steve", SteveAddress, 17408, 18432)
	c.CollectUDPSessionDownlink("Alex", AlexAddress, 1024, 19456)
	c.CollectUDPSessionUplink("Alex", AlexAddress, 2048, 20480)
}

func collectNoUsername(t *testing.T, c Collector) {
	t.Helper()
	c.CollectTCPSession("", "", 1024, 2048)
	c.CollectUDPSessionDownlink("", "", 1, 3072)
	c.CollectUDPSessionUplink("", "", 2, 4096)
}

func verify(t *testing.T, s Server) {
	t.Helper()
	expectedServerTraffic := Traffic{
		DownlinkPackets: 1142,
		DownlinkBytes:   100352,
		UplinkPackets:   2953,
		UplinkBytes:     114688,
		TCPSessions:     4,
		UDPSessions:     6,
	}
	expectedSteveTraffic := Traffic{
		DownlinkPackets: 34,
		DownlinkBytes:   44032,
		UplinkPackets:   136,
		UplinkBytes:     53248,
		TCPSessions:     3,
		UDPSessions:     2,
	}
	expectedAlexTraffic := Traffic{
		DownlinkPackets: 1108,
		DownlinkBytes:   56320,
		UplinkPackets:   2817,
		UplinkBytes:     61440,
		TCPSessions:     1,
		UDPSessions:     4,
	}

	if s.Traffic != expectedServerTraffic {
		t.Errorf("expected server traffic %+v, got %+v", expectedServerTraffic, s.Traffic)
	}
	if len(s.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(s.Users))
	}
	for _, u := range s.Users {
		t.Logf("user: %v: %+v", u.Name, u)

		if u.Metadata.LastSessionTimestamp == 0 {
			t.Errorf("expected non-zero last session timestamp for user %s", u.Name)
		}

		switch u.Name {
		case "Steve":
			if u.Traffic != expectedSteveTraffic {
				t.Errorf("expected Steve traffic %+v, got %+v", expectedSteveTraffic, u.Traffic)
			}
			if u.Metadata.LastSessionClientAddress != SteveAddress {
				t.Errorf("expected Steve address %v, got %v", SteveAddress, u.Metadata.LastSessionClientAddress)
			}
		case "Alex":
			if u.Traffic != expectedAlexTraffic {
				t.Errorf("expected Alex traffic %+v, got %+v", expectedAlexTraffic, u.Traffic)
			}
			if u.Metadata.LastSessionClientAddress != AlexAddress {
				t.Errorf("expected Alex address %v, got %v", AlexAddress, u.Metadata.LastSessionClientAddress)
			}
		default:
			t.Errorf("unexpected user %s", u.Name)
		}
	}
}

func verifyNoUsername(t *testing.T, s Server) {
	t.Helper()
	expectedServerTraffic := Traffic{
		DownlinkPackets: 1,
		DownlinkBytes:   4096,
		UplinkPackets:   2,
		UplinkBytes:     6144,
		TCPSessions:     1,
		UDPSessions:     1,
	}

	if s.Traffic != expectedServerTraffic {
		t.Errorf("expected server traffic %+v, got %+v", expectedServerTraffic, s.Traffic)
	}
	if len(s.Users) != 0 {
		t.Errorf("expected zero users, got %d", len(s.Users))
	}
}

func verifyEmpty(t *testing.T, s Server) {
	t.Helper()
	var zero Traffic
	if s.Traffic != zero {
		t.Errorf("expected zero traffic, got %+v", s.Traffic)
	}
	for _, u := range s.Users {
		if u.Traffic != zero {
			t.Errorf("expected zero traffic for user %s, got %+v", u.Name, u.Traffic)
		}
	}
}

func TestServerCollector(t *testing.T) {
	c := Config{Enabled: true}.Collector()
	collectNoUsername(t, c)
	verifyNoUsername(t, c.Snapshot())
	verifyNoUsername(t, c.SnapshotAndReset())
	verifyEmpty(t, c.Snapshot())
	collect(t, c)
	verify(t, c.Snapshot())
	verify(t, c.SnapshotAndReset())
	verifyEmpty(t, c.Snapshot())
}

func TestNoopCollector(t *testing.T) {
	c := Config{}.Collector()
	collectNoUsername(t, c)
	verifyEmpty(t, c.Snapshot())
	verifyEmpty(t, c.SnapshotAndReset())
	verifyEmpty(t, c.Snapshot())
	collect(t, c)
	verifyEmpty(t, c.Snapshot())
	verifyEmpty(t, c.SnapshotAndReset())
	verifyEmpty(t, c.Snapshot())
}
