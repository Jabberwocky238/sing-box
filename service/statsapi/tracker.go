package statsapi

import (
	"context"
	"net"
	"sort"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*Tracker)(nil)

type counter struct {
	upload   atomic.Int64
	download atomic.Int64
}

func (c *counter) take(clear bool) (int64, int64) {
	if clear {
		return c.upload.Swap(0), c.download.Swap(0)
	}
	return c.upload.Load(), c.download.Load()
}

// inboundInfo identifies one proxy entry point (one row of the enzyme proxies table).
type inboundInfo struct {
	Tag  string
	Type string
	Port uint16
}

type inboundCounter struct {
	inboundInfo
	counter
}

// Tracker counts traffic per inbound and per user per inbound.
// Counters are never removed: live connections keep pointers to them.
type Tracker struct {
	access   sync.RWMutex
	inbounds map[string]*inboundCounter
	users    map[string]map[string]*inboundCounter // user -> inbound tag -> counter
}

func NewTracker() *Tracker {
	return &Tracker{
		inbounds: make(map[string]*inboundCounter),
		users:    make(map[string]map[string]*inboundCounter),
	}
}

func infoFromMetadata(metadata adapter.InboundContext) inboundInfo {
	return inboundInfo{
		Tag:  metadata.Inbound,
		Type: metadata.InboundType,
		Port: metadata.OriginDestination.Port,
	}
}

func newInboundCounter(info inboundInfo) *inboundCounter {
	return &inboundCounter{inboundInfo: info}
}

func (t *Tracker) counters(metadata adapter.InboundContext) (read []*atomic.Int64, write []*atomic.Int64) {
	if metadata.Inbound == "" {
		return nil, nil
	}
	info := infoFromMetadata(metadata)
	t.access.Lock()
	defer t.access.Unlock()
	inbound := t.inbounds[info.Tag]
	if inbound == nil {
		inbound = newInboundCounter(info)
		t.inbounds[info.Tag] = inbound
	} else if inbound.Port == 0 && info.Port != 0 {
		inbound.Port = info.Port
	}
	read = append(read, &inbound.upload)
	write = append(write, &inbound.download)
	if metadata.User == "" {
		return read, write
	}
	userInbounds := t.users[metadata.User]
	if userInbounds == nil {
		userInbounds = make(map[string]*inboundCounter)
		t.users[metadata.User] = userInbounds
	}
	user := userInbounds[info.Tag]
	if user == nil {
		user = newInboundCounter(inbound.inboundInfo)
		userInbounds[info.Tag] = user
	} else if user.Port == 0 && info.Port != 0 {
		user.Port = info.Port
	}
	read = append(read, &user.upload)
	write = append(write, &user.download)
	return read, write
}

func (t *Tracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	read, write := t.counters(metadata)
	if len(read) == 0 {
		return conn
	}
	return bufio.NewInt64CounterConn(conn, read, write)
}

func (t *Tracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	read, write := t.counters(metadata)
	if len(read) == 0 {
		return conn
	}
	return bufio.NewInt64CounterPacketConn(conn, read, nil, write, nil)
}

func (t *Tracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

type TrafficEntry struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type InboundEntry struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	Port     uint16 `json:"port,omitempty"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

type UserEntry struct {
	Email string `json:"email"`
	// Protocols aggregates by inbound type (legacy format consumed by enzyme).
	Protocols map[string]TrafficEntry `json:"protocols"`
	// Inbounds is the per entry point split (tag/type/port), for exact proxy mapping.
	Inbounds []InboundEntry `json:"inbounds"`
}

type Snapshot struct {
	Inbounds []InboundEntry `json:"inbounds"`
	Users    []UserEntry    `json:"users"`
}

// Snapshot reads (and with clear=true atomically resets) all counters.
// Entries without traffic are omitted.
func (t *Tracker) Snapshot(clear bool) Snapshot {
	t.access.RLock()
	defer t.access.RUnlock()
	snapshot := Snapshot{
		Inbounds: make([]InboundEntry, 0, len(t.inbounds)),
		Users:    make([]UserEntry, 0, len(t.users)),
	}
	for _, inbound := range t.inbounds {
		upload, download := inbound.take(clear)
		if upload == 0 && download == 0 {
			continue
		}
		snapshot.Inbounds = append(snapshot.Inbounds, InboundEntry{inbound.Tag, inbound.Type, inbound.Port, upload, download})
	}
	for user, userInbounds := range t.users {
		entry := UserEntry{Email: user, Protocols: make(map[string]TrafficEntry)}
		for _, inbound := range userInbounds {
			upload, download := inbound.take(clear)
			if upload == 0 && download == 0 {
				continue
			}
			entry.Inbounds = append(entry.Inbounds, InboundEntry{inbound.Tag, inbound.Type, inbound.Port, upload, download})
			protocol := entry.Protocols[inbound.Type]
			protocol.Upload += upload
			protocol.Download += download
			entry.Protocols[inbound.Type] = protocol
		}
		if len(entry.Inbounds) == 0 {
			continue
		}
		sort.Slice(entry.Inbounds, func(i, j int) bool { return entry.Inbounds[i].Tag < entry.Inbounds[j].Tag })
		snapshot.Users = append(snapshot.Users, entry)
	}
	sort.Slice(snapshot.Inbounds, func(i, j int) bool { return snapshot.Inbounds[i].Tag < snapshot.Inbounds[j].Tag })
	sort.Slice(snapshot.Users, func(i, j int) bool { return snapshot.Users[i].Email < snapshot.Users[j].Email })
	return snapshot
}
