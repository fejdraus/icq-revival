// Command e2e-kt-auditor audits the key transparency log of an ICQ Revival
// key directory (docs/e2e/KEY-TRANSPARENCY.md, stage 2), as Signal's key
// transparency auditors do: it follows the log, checks that it only grows
// and that every entry keeps the directory's rules, and hands the server a
// cosignature over each checkpoint it checked. Clients accept the log only
// with a recent cosignature by an auditor they know.
//
// It should run somewhere the server's operator does not control alone. It
// needs outbound HTTPS to the directory and nothing else.
// deploy/e2e-kt-auditor has a systemd unit and an install script for it; a
// server may have several auditors (E2E_KT_AUDITORS is a comma list).
//
//	e2e-kt-auditor -log https://icq.example.org:8102/e2e/v1/ -name auditor.example.org/icq -key auditor.key -state auditor.json
//	e2e-kt-auditor -key auditor.key -name auditor.example.org/icq -print-key
//
// The key file is made on first use. -print-key prints the verifier key the
// server's operator puts into E2E_KT_AUDITORS. A violation of the log exits with
// status 3, for good: the state file records it.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/server/e2e"
)

func main() {
	base := flag.String("log", "", "the key directory's URL, ending in /e2e/v1/")
	name := flag.String("name", "", "this auditor's name, a schema-less URL such as auditor.example.org/icq")
	keyFile := flag.String("key", "auditor.key", "this auditor's Ed25519 seed; made on first use")
	stateFile := flag.String("state", "auditor.json", "what the auditor has checked so far")
	every := flag.Duration("interval", time.Minute, "how often the log is checked and cosigned")
	printKey := flag.Bool("print-key", false, "print the verifier key for E2E_KT_AUDITORS and exit")
	once := flag.Bool("once", false, "check and cosign once, then exit")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if *name == "" || strings.ContainsAny(*name, " +\n") {
		fail(logger, "-name is required, without spaces or plus signs")
	}
	priv, err := loadKey(*keyFile)
	if err != nil {
		fail(logger, "key", "err", err)
	}
	if *printKey {
		fmt.Println(e2e.CosignerKey(*name, priv.Public().(ed25519.PublicKey)))
		return
	}
	if *base == "" {
		fail(logger, "-log is required")
	}
	if !strings.HasSuffix(*base, "/") {
		*base += "/"
	}

	st, err := loadState(*stateFile)
	if err != nil {
		fail(logger, "state", "err", err)
	}
	a := &e2e.Auditor{
		Base:   *base,
		Name:   *name,
		Key:    priv,
		Client: &http.Client{Timeout: 30 * time.Second},
		Now:    time.Now,
	}
	logger.Info("auditing", "log", *base, "auditor", e2e.CosignerKey(*name, priv.Public().(ed25519.PublicKey)))
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		err := a.Step(ctx, st)
		cancel()
		if serr := saveState(*stateFile, st); serr != nil {
			logger.Error("state not saved", "err", serr)
		}
		switch {
		case errors.Is(err, e2e.ErrViolation):
			// Loud and for good: the auditor never cosigns this log again.
			// Exit status 3 leaves a systemd unit failed (with
			// RestartPreventExitStatus=3), which monitoring reports.
			logger.Error("KEY LOG VIOLATION - no longer cosigning", "why", st.Violation)
			os.Exit(3)
		case err != nil:
			logger.Warn("not cosigned this time", "err", err)
		default:
			logger.Info("cosigned", "size", st.Size)
		}
		if *once {
			if err != nil {
				os.Exit(1)
			}
			return
		}
		time.Sleep(*every)
	}
}

func fail(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(2)
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func loadState(path string) (*e2e.AuditState, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &e2e.AuditState{}, nil
	}
	if err != nil {
		return nil, err
	}
	var st e2e.AuditState
	return &st, json.Unmarshal(raw, &st)
}

func saveState(path string, st *e2e.AuditState) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
