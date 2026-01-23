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

type UserCounter struct {
	Counter
	Protocol string
}

type Tracker struct {
	access   sync.RWMutex
	inbounds map[string]*Counter
	users    map[string]*UserCounter
}

func NewTracker() *Tracker {
	return &Tracker{
		inbounds: make(map[string]*Counter),
		users:    make(map[string]*UserCounter),
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

func (t *Tracker) getOrCreateUserCounter(user string, protocol string) *UserCounter {
	if user == "" {
		return nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	counter, ok := t.users[user]
	if !ok {
		counter = &UserCounter{
			Counter: Counter{
				Upload:   &atomic.Int64{},
				Download: &atomic.Int64{},
			},
			Protocol: protocol,
		}
		t.users[user] = counter
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
	Tag      string `json:"tag"`
	Protocol string `json:"protocol,omitempty"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
}

func (t *Tracker) GetInboundStats(clear bool) []StatsEntry {
	t.access.RLock()
	defer t.access.RUnlock()

	result := make([]StatsEntry, 0, len(t.inbounds))
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
			result = append(result, StatsEntry{Tag: tag, Upload: up, Download: down})
		}
	}
	return result
}

func (t *Tracker) GetUserStats(clear bool) []StatsEntry {
	t.access.RLock()
	defer t.access.RUnlock()

	result := make([]StatsEntry, 0, len(t.users))
	for tag, counter := range t.users {
		var up, down int64
		if clear {
			up = counter.Upload.Swap(0)
			down = counter.Download.Swap(0)
		} else {
			up = counter.Upload.Load()
			down = counter.Download.Load()
		}
		if up > 0 || down > 0 {
			result = append(result, StatsEntry{Tag: tag, Protocol: counter.Protocol, Upload: up, Download: down})
		}
	}
	return result
}
