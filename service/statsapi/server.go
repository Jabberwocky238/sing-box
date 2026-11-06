// Package statsapi exposes per user / per inbound traffic counters and a kick
// endpoint over HTTP, for the enzyme billing pipeline.
//
//	GET  /stats[?clear=true]  traffic snapshot (clear resets the counters it returns)
//	POST /kick                ["user", ...] or {"users": [...], "ban_seconds": N}
//	GET  /online              live session count per user
package statsapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/usersession"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"golang.org/x/net/http2"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.StatsAPIServiceOptions](registry, C.TypeStatsAPI, NewService)
}

type Service struct {
	boxService.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	httpServer *http.Server
	tracker    *Tracker
	sessions   *usersession.Registry
	authToken  string
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.StatsAPIServiceOptions) (adapter.Service, error) {
	chiRouter := chi.NewRouter()
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeStatsAPI, tag),
		ctx:     ctx,
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
		httpServer: &http.Server{Handler: chiRouter, ReadHeaderTimeout: 10 * time.Second},
		tracker:    NewTracker(),
		sessions:   usersession.FromContext(ctx),
		authToken:  options.AuthToken,
	}
	if s.authToken != "" {
		chiRouter.Use(s.authMiddleware)
	}
	chiRouter.Get("/stats", s.getStats)
	chiRouter.Post("/kick", s.postKick)
	chiRouter.Get("/online", s.getOnline)
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsConfig
	}
	service.FromContext[adapter.Router](ctx).AppendTracker(s.tracker)
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(s.tlsConfig.Close)
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{"h2"}, s.tlsConfig.NextProtos()...))
		}
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	scope.Add(s.httpServer.Close)
	go func() {
		serveErr := s.httpServer.Serve(tcpListener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("serve error: ", serveErr)
		}
	}()
	return nil
}

func (s *Service) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(s.authToken)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) getStats(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, s.tracker.Snapshot(r.URL.Query().Get("clear") == "true"))
}

type kickRequest struct {
	Users      []string `json:"users"`
	BanSeconds int      `json:"ban_seconds"`
}

func (s *Service) postKick(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var request kickRequest
	// accept a bare array (legacy enzyme innerKickUser) or an object
	if err = json.Unmarshal(body, &request.Users); err != nil {
		request = kickRequest{}
		if err = json.Unmarshal(body, &request); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
	}
	users := common.Filter(request.Users, func(it string) bool { return it != "" })
	kicked := s.sessions.Kick(users, time.Duration(max(request.BanSeconds, 0))*time.Second)
	s.logger.Info("kick [", strings.Join(users, ","), "]: ", kicked, " session(s) closed")
	render.JSON(w, r, render.M{"users": users, "kicked": kicked})
}

func (s *Service) getOnline(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, s.sessions.Online())
}
