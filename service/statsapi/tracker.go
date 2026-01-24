package statsapi

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.ConnectionTracker = (*Tracker)(nil)

type Counter struct {
	Upload   *atomic.Int64
	Download *atomic.Int64
}

type Tracker struct {
	access   sync.RWMutex
	inbounds map[string]*Counter
	users    map[string]map[string]*Counter // user -> protocol -> counter
}

func NewTracker() *Tracker {
	return &Tracker{
		inbounds: make(map[string]*Counter),
		users:    make(map[string]map[string]*Counter),
	}
}

func (t *Tracker) getOrCreateCounter(m map[string]*Counter, key string) *Counter {
	if key == "" {
		return nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	counter, ok := m[key]
	if !ok {
		counter = &Counter{
			Upload:   &atomic.Int64{},
			Download: &atomic.Int64{},
		}
		m[key] = counter
	}
	return counter
}

func (t *Tracker) getOrCreateUserCounter(user string, protocol string) *Counter {
	if user == "" || protocol == "" {
		return nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	protocolMap, ok := t.users[user]
	if !ok {
		protocolMap = make(map[string]*Counter)
		t.users[user] = protocolMap
	}
	counter, ok := protocolMap[protocol]
	if !ok {
		counter = &Counter{
			Upload:   &atomic.Int64{},
			Download: &atomic.Int64{},
		}
		protocolMap[protocol] = counter
	}
	return counter
}

func (t *Tracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	var readCounter []*atomic.Int64
	var writeCounter []*atomic.Int64

	if inboundCounter := t.getOrCreateCounter(t.inbounds, metadata.Inbound); inboundCounter != nil {
		readCounter = append(readCounter, inboundCounter.Upload)
		writeCounter = append(writeCounter, inboundCounter.Download)
	}
	if userCounter := t.getOrCreateUserCounter(metadata.User, metadata.InboundType); userCounter != nil {
		readCounter = append(readCounter, userCounter.Upload)
		writeCounter = append(writeCounter, userCounter.Download)
	}

	if len(readCounter) == 0 {
		return conn
	}
	return bufio.NewInt64CounterConn(conn, readCounter, writeCounter)
}

func (t *Tracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	var readCounter []*atomic.Int64
	var writeCounter []*atomic.Int64

	if inboundCounter := t.getOrCreateCounter(t.inbounds, metadata.Inbound); inboundCounter != nil {
		readCounter = append(readCounter, inboundCounter.Upload)
		writeCounter = append(writeCounter, inboundCounter.Download)
	}
	if userCounter := t.getOrCreateUserCounter(metadata.User, metadata.InboundType); userCounter != nil {
		readCounter = append(readCounter, userCounter.Upload)
		writeCounter = append(writeCounter, userCounter.Download)
	}

	if len(readCounter) == 0 {
		return conn
	}
	return bufio.NewInt64CounterPacketConn(conn, readCounter, nil, writeCounter, nil)
}

type StatsEntry struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}

type StatsInboundEntry struct {
	Tag      string `json:"tag"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

func (t *Tracker) GetInboundStats(clear bool) []StatsInboundEntry {
	t.access.RLock()
	defer t.access.RUnlock()

	result := make([]StatsInboundEntry, 0, len(t.inbounds))
	for tag, counter := range t.inbounds {
		var up, down int64
		if clear {
			up = counter.Upload.Swap(0)
			down = counter.Download.Swap(0)
		} else {
			up = counter.Upload.Load()
			down = counter.Download.Load()
		}
		if up > 0 || down > 0 {
			result = append(result, StatsInboundEntry{Tag: tag, Upload: up, Download: down})
		}
	}
	return result
}

type StatsUserEntry struct {
	Email     string                `json:"email"`
	Protocols map[string]StatsEntry `json:"protocols"`
}

func (t *Tracker) GetUserStats(clear bool) []StatsUserEntry {
	t.access.RLock()
	defer t.access.RUnlock()

	var result []StatsUserEntry
	for user, protocolMap := range t.users {
		result = append(result, StatsUserEntry{
			Email:     user,
			Protocols: make(map[string]StatsEntry),
		})
		for protocol, counter := range protocolMap {
			var up, down int64
			if clear {
				up = counter.Upload.Swap(0)
				down = counter.Download.Swap(0)
			} else {
				up = counter.Upload.Load()
				down = counter.Download.Load()
			}
			if up > 0 || down > 0 {
				result[len(result)-1].Protocols[protocol] = StatsEntry{Upload: up, Download: down}
			}
		}
	}
	return result
}
