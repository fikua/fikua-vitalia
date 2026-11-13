// Command vitalia runs Clínica Vitalia, a fake healthcare platform that
// enrols its physicians through the DoctorID enrolment API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fikua/fikua-vitalia/internal/cgcom"
	"github.com/fikua/fikua-vitalia/internal/config"
	"github.com/fikua/fikua-vitalia/internal/doctorlogin"
	"github.com/fikua/fikua-vitalia/internal/enrollment"
	"github.com/fikua/fikua-vitalia/internal/store"
	"github.com/fikua/fikua-vitalia/internal/web"
	"github.com/fikua/fikua-vitalia/internal/webhook"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("vitalia stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	var tokens cgcom.TokenSource = cgcom.StaticTokenSource(cfg.AdapterToken)
	if cfg.CGCOMTokenURL != "" {
		tokens, err = cgcom.NewPrivateKeyJWTSource(cgcom.TokenConfig{
			TokenURL: cfg.CGCOMTokenURL, ClientID: cfg.CGCOMClientID, Key: cfg.CGCOMSigningKey,
			Audience: cfg.CGCOMTokenAudience, Scope: cfg.CGCOMTokenScope, HTTP: &http.Client{Timeout: cfg.AdapterTimeout},
		})
		if err != nil {
			return err
		}
	}
	client := cgcom.NewClient(cfg.AdapterBaseURL, &http.Client{Timeout: cfg.AdapterTimeout}, tokens, st)
	svc := enrollment.New(st, client, logger, cfg.RefreshOnWebhook)
	receiver := &webhook.Receiver{Secret: cfg.WebhookSecret, Tolerance: cfg.SignatureTolerance, Sink: st,
		Notify: svc.Wake, Logger: logger}
	var login *doctorlogin.Client
	if cfg.OIDCIssuer != "" {
		login, err = doctorlogin.New(doctorlogin.Config{
			Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, RedirectURL: cfg.PublicURL.JoinPath("/profesional/callback").String(),
			Scopes: cfg.OIDCScopes, ACR: cfg.OIDCACR, SigningKey: cfg.OIDCSigningKey, Secret: cfg.OIDCSecret,
			HTTP: &http.Client{Timeout: 15 * time.Second},
		})
		if err != nil {
			return err
		}
	}
	var staff *doctorlogin.Client
	if cfg.StaffOIDCIssuer != "" {
		staff, err = doctorlogin.New(doctorlogin.Config{
			Issuer: cfg.StaffOIDCIssuer, ClientID: cfg.StaffOIDCClientID, Secret: cfg.StaffOIDCSecret,
			RedirectURL: cfg.PublicURL.JoinPath("/gestion/callback").String(), Scopes: []string{"openid", "profile", "email"},
			HTTP: &http.Client{Timeout: 15 * time.Second},
		})
		if err != nil {
			return err
		}
	}
	ui, err := web.New(web.Config{UIUser: cfg.UIUser, UIPassword: cfg.UIPassword, CookieSecure: cfg.CookieSecure,
		AdapterHost: cfg.AdapterBaseURL.String(), StaffLogin: staff, StaffGroup: cfg.StaffGroup}, st, svc, receiver, login, logger)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: cfg.ListenAddr, Handler: ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
	}

	var wg sync.WaitGroup
	// Short safety-net interval: it also adopts the directory's enrolments.
	wg.Go(func() { svc.Run(ctx, 10*time.Second) })

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "adapter", cfg.AdapterBaseURL.String(), "oidc_issuer", cfg.OIDCIssuer, "staff_oidc_issuer", cfg.StaffOIDCIssuer,
			"token_configured", cfg.AdapterToken != "", "cgcom_private_key_jwt", cfg.CGCOMTokenURL != "", "webhook_path", web.WebhookPath)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		stop()
		wg.Wait()
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
