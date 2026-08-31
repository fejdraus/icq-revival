package handlers

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ExpressionsData lists the expressions (buddy icons, etc.) a user publishes.
type ExpressionsData struct {
	Expressions []Expression `json:"expressions" xml:"expressions>expression"`
}

// Expression is one published asset.
type Expression struct {
	Type string `json:"type" xml:"type"`
	URL  string `json:"url" xml:"url"`
}

const bartUploadMaxBytes = 64 << 10

// BARTUploader stores a BART asset and returns its content-addressed ID.
type BARTUploader interface {
	UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error)
}

// ExpressionsFeedbagService is the slice of the feedbag service Upload needs to
// point a user's icon reference at a newly stored asset.
type ExpressionsFeedbagService interface {
	Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error)
	UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, items []wire.FeedbagItem) (*wire.SNACMessage, error)
}

// ExpressionsHandler handles Web AIM API expressions/buddy icon endpoints.
type ExpressionsHandler struct {
	IconSource     BuddyIconSource
	BARTUploader   BARTUploader
	FeedbagService ExpressionsFeedbagService
	Logger         *slog.Logger
}

// NewExpressionsHandler creates a new ExpressionsHandler.
func NewExpressionsHandler(
	iconSource BuddyIconSource,
	bartUploader BARTUploader,
	feedbagService ExpressionsFeedbagService,
	logger *slog.Logger,
) *ExpressionsHandler {
	return &ExpressionsHandler{
		IconSource:     iconSource,
		BARTUploader:   bartUploader,
		FeedbagService: feedbagService,
		Logger:         logger,
	}
}

// Get handles GET /expressions/get requests for buddy icons and expressions.
//
// The AIM client calls this endpoint two different ways:
//
//   - With type=buddyIcon it fetches the image itself. The buddyIcon URL
//     published in presence, buddylist and myInfo payloads points here, and the
//     client renders it directly as an <img> source.
//   - With no type it asks for the user's expressions as JSON, then scans the
//     returned array for the entry typed bigBuddyIcon and uses its url to render
//     hovercards and other large views. We have only one icon per user, so it is
//     offered as both.
func (h *ExpressionsHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	target := r.URL.Query().Get("t")
	if target == "" {
		SendError(w, r, http.StatusBadRequest, "missing target")
		return
	}
	screenName := state.NewIdentScreenName(target)

	switch r.URL.Query().Get("type") {
	case "buddyIcon", "bigBuddyIcon":
		h.serveIcon(w, r, screenName)
		return
	}

	iconURL := h.IconSource.URL(ctx, baseURLFromRequest(r), screenName)

	// f=redirect asks for the icon itself rather than a description of it.
	if r.URL.Query().Get("f") == "redirect" {
		if iconURL == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Redirect(w, r, iconURL, http.StatusFound)
		return
	}

	expressions := []Expression{}
	if iconURL != "" {
		expressions = append(expressions, Expression{Type: "bigBuddyIcon", URL: iconURL})
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &ExpressionsData{Expressions: expressions}
	SendResponse(w, r, resp, h.Logger)
}

// serveIcon writes a user's buddy icon image.
//
// A bartId names an exact image by content hash, so the endpoint serves that
// image regardless of the user's current icon and lets browsers cache it
// forever. Without a bartId it serves whatever the user's icon is now — which
// keeps changing — so that response is not cacheable, and a user with no icon
// gets the blank placeholder so the client's <img> still renders.
func (h *ExpressionsHandler) serveIcon(w http.ResponseWriter, r *http.Request, screenName state.IdentScreenName) {
	ctx := r.Context()

	var (
		icon      []byte
		err       error
		immutable bool
	)
	if raw := r.URL.Query().Get("bartId"); raw != "" {
		hash, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil || len(hash) == 0 {
			http.Error(w, "invalid bartId", http.StatusBadRequest)
			return
		}
		icon, err = h.IconSource.ImageForHash(ctx, screenName, hash)
		immutable = true
	} else {
		icon, err = h.IconSource.Image(ctx, screenName)
		if errors.Is(err, ErrNoBuddyIcon) {
			// Serve the blank placeholder rather than 404 so a cleared icon still
			// renders something and the client stops showing the previous one.
			icon, err = h.IconSource.ImageForHash(ctx, screenName, wire.GetClearIconHash())
		}
	}

	switch {
	case errors.Is(err, ErrNoBuddyIcon):
		// The client swaps in its own placeholder when the icon fails to load.
		http.Error(w, "icon not found", http.StatusNotFound)
		return
	case err != nil:
		h.Logger.ErrorContext(ctx, "failed to retrieve buddy icon",
			"screenName", screenName.String(), "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if immutable {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	w.Header().Set("Content-Type", http.DetectContentType(icon))
	_, _ = w.Write(icon)
}

// UploadData is the payload of an expressions/upload response. The id is the
// BART type followed by the asset's content hash; setExpression takes the same
// string with the leading four hex digits (the type) stripped off.
type UploadData struct {
	ID string `json:"id" xml:"id"`
}

// Upload handles POST /expressions/upload, which stores a buddy icon.
func (h *ExpressionsHandler) Upload(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
	ctx := r.Context()

	var bartType uint16
	switch t := r.URL.Query().Get("type"); t {
	case "buddyIcon", "bigBuddyIcon":
		bartType = wire.BARTTypesBuddyIcon
	case "":
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0,
			"required parameter 'type' is missing")
		return
	default:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0,
			"unsupported expression type")
		return
	}

	// One byte past the cap distinguishes "exactly at the limit" from "over it".
	image, err := io.ReadAll(io.LimitReader(r.Body, bartUploadMaxBytes+1))
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to read upload body", "err", err.Error())
		SendError(w, r, http.StatusBadRequest, "failed to read request body")
		return
	}
	switch {
	case len(image) == 0:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, "empty image")
		return
	case len(image) > bartUploadMaxBytes:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, "image too large")
		return
	}

	uploadReply, err := h.BARTUploader.UpsertItem(ctx, session.OSCARSession,
		wire.SNACFrame{FoodGroup: wire.BART, SubGroup: wire.BARTUploadQuery},
		wire.SNAC_0x10_0x02_BARTUploadQuery{Type: bartType, Data: image})
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to store BART item", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}

	body, ok := uploadReply.Body.(wire.SNAC_0x10_0x03_BARTUploadReply)
	if !ok {
		h.Logger.ErrorContext(ctx, "unexpected BART upload reply",
			"type", fmt.Sprintf("%T", uploadReply.Body))
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}
	if body.Code != wire.BARTReplyCodesSuccess {
		h.Logger.ErrorContext(ctx, "BART store rejected upload", "code", body.Code)
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}

	if err := h.publishIcon(ctx, session.OSCARSession, bartType, body.ID.Hash); err != nil {
		h.Logger.ErrorContext(ctx, "failed to publish buddy icon",
			"screenName", session.OSCARSession.IdentScreenName().String(), "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to publish expression")
		return
	}

	h.Logger.InfoContext(ctx, "stored buddy icon",
		"screenName", session.OSCARSession.IdentScreenName().String(),
		"bytes", len(image),
		"hash", fmt.Sprintf("%x", body.ID.Hash))

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "Ok"
	resp.Response.Data = &UploadData{ID: fmt.Sprintf("%04x%x", bartType, body.ID.Hash)}
	SendResponse(w, r, resp, h.Logger)
}

// publishIcon points the user's feedbag BART reference at hash, which is what
// makes the icon visible to buddies and to expressions/get.
//
// Upserting the item runs the same path an OSCAR client takes when it sets an
// icon: the feedbag service sees the asset already in the BART store, stamps it
// on the session and broadcasts the change to buddies.
func (h *ExpressionsHandler) publishIcon(
	ctx context.Context,
	instance *state.SessionInstance,
	bartType uint16,
	hash []byte,
) error {
	msg, err := h.FeedbagService.Query(ctx, instance,
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery})
	if err != nil {
		return err
	}
	reply, ok := msg.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return fmt.Errorf("unexpected feedbag reply %T", msg.Body)
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	item, inserted := fl.SetIcon(bartType, hash)

	subGroup := wire.FeedbagUpdateItem
	if inserted {
		subGroup = wire.FeedbagInsertItem
	}

	_, err = h.FeedbagService.UpsertItem(ctx, instance,
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: subGroup},
		[]wire.FeedbagItem{item})
	return err
}
