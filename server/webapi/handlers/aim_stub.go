package handlers

import (
	"log/slog"
	"net/http"
)

// AimStubHandler serves unimplemented Web AIM /aim/* endpoints the client
// calls during normal startup (client-side storage, forward-domain config).
type AimStubHandler struct {
	Logger *slog.Logger
}

// SetForwardDomain acknowledges the client's forward-domain registration.
// The Web AIM client fires this once when the session goes online; name may be
// the literal string "null" for local/dev servers.
func (h *AimStubHandler) SetForwardDomain(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// ReportAction acknowledges a client-side UI telemetry ping. The Web AIM client
// fires this on menu clicks and similar interactions with an action param of the
// form "type=click,id=block-user-chatmenu"; it ignores the response.
func (h *AimStubHandler) ReportAction(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// StoredDataItems is the client-side data blob store, which this server does
// not keep, so it always answers with an empty items list.
type StoredDataItems struct {
	Items []string `json:"items" xml:"items>item"`
}

// GetData returns empty client-side data blobs (buddy list favorites, etc.).
func (h *AimStubHandler) GetData(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &StoredDataItems{Items: []string{}}
	SendResponse(w, r, resp, h.Logger)
}
