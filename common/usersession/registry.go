// Package usersession tracks live authenticated sessions per user so they can be
// kicked (closed) on demand, e.g. when a user runs out of traffic quota.
package usersession

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sagernet/sing/service"
)

// ErrKicked is the cancel cause of a kicked session.
var ErrKicked = errors.New("session kicked")

type Registry struct {
	access       sync.Mutex
	nextID       uint64
	sessions     map[string]map[uint64]context.CancelCauseFunc
	bans         map[string]time.Time
	invalidators []func(user string)
}

func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]map[uint64]context.CancelCauseFunc),
		bans:     make(map[string]time.Time),
	}
}

// FromContext returns the registry shared by every component of one box
// instance, creating and registering it on first use.
func FromContext(ctx context.Context) *Registry {
	if registry := service.PtrFromContext[Registry](ctx); registry != nil {
		return registry
	}
	registry := NewRegistry()
	service.ContextWithPtr(ctx, registry)
	return registry
}

// Open derives a cancellable session context for user. Cancelling it (via Kick)
// tears down the session. release must be called when the session ends.
func (r *Registry) Open(ctx context.Context, user string) (sessionCtx context.Context, release func()) {
	sessionCtx, cancel := context.WithCancelCause(ctx)
	r.access.Lock()
	r.nextID++
	id := r.nextID
	userSessions := r.sessions[user]
	if userSessions == nil {
		userSessions = make(map[uint64]context.CancelCauseFunc)
		r.sessions[user] = userSessions
	}
	userSessions[id] = cancel
	r.access.Unlock()
	var once sync.Once
	return sessionCtx, func() {
		once.Do(func() {
			r.access.Lock()
			if userSessions := r.sessions[user]; userSessions != nil {
				delete(userSessions, id)
				if len(userSessions) == 0 {
					delete(r.sessions, user)
				}
			}
			r.access.Unlock()
			cancel(nil)
		})
	}
}

// Banned reports whether user is temporarily refused new sessions.
func (r *Registry) Banned(user string) bool {
	r.access.Lock()
	defer r.access.Unlock()
	until, loaded := r.bans[user]
	if !loaded {
		return false
	}
	if time.Now().After(until) {
		delete(r.bans, user)
		return false
	}
	return true
}

// OnKick registers a callback run for every kicked user (e.g. to drop auth caches).
func (r *Registry) OnKick(invalidator func(user string)) {
	r.access.Lock()
	r.invalidators = append(r.invalidators, invalidator)
	r.access.Unlock()
}

// Kick closes every live session of the given users and returns how many were
// closed. With ban > 0 the users are also refused new sessions for that long.
func (r *Registry) Kick(users []string, ban time.Duration) int {
	var cancels []context.CancelCauseFunc
	r.access.Lock()
	for _, user := range users {
		for _, cancel := range r.sessions[user] {
			cancels = append(cancels, cancel)
		}
		delete(r.sessions, user)
		if ban > 0 {
			r.bans[user] = time.Now().Add(ban)
		}
	}
	invalidators := append([]func(string){}, r.invalidators...)
	r.access.Unlock()
	for _, invalidate := range invalidators {
		for _, user := range users {
			invalidate(user)
		}
	}
	for _, cancel := range cancels {
		cancel(ErrKicked)
	}
	return len(cancels)
}

// Online returns the number of live sessions per user.
func (r *Registry) Online() map[string]int {
	r.access.Lock()
	defer r.access.Unlock()
	result := make(map[string]int, len(r.sessions))
	for user, userSessions := range r.sessions {
		result[user] = len(userSessions)
	}
	return result
}
