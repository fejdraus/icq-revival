package handlers

import (
	"log/slog"
	"net/http"
)

type UserInfoStubHandler struct {
	Logger *slog.Logger
}

// UserDetailsData reports which third-party services the account is linked to.
type UserDetailsData struct {
	UserDetails UserDetails `json:"userDetails" xml:"userDetails"`
}

// UserDetails lists the linked services.
type UserDetails struct {
	Services []UserService `json:"services" xml:"services>service"`
}

// UserService names one linked service.
type UserService struct {
	Service string `json:"service" xml:"service"`
}

// NotificationsData is the social-notification feed, which this server does not
// keep.
type NotificationsData struct {
	// Activities is always sent, empty included: the client maps over it
	// unconditionally on a 200.
	Activities []string `json:"activities" xml:"activities>activity"`
}

func (h *UserInfoStubHandler) GetUserDetails(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &UserDetailsData{
		UserDetails: UserDetails{Services: []UserService{{Service: "aim"}}},
	}
	SendResponse(w, r, resp, h.Logger)
}

// HeyGetNotifications returns an empty social-notification feed.
//
// The activities array must be present even when empty: the client maps over
// response.data.activities unconditionally on a 200, so omitting it raises
// "Array.prototype.map called on null or undefined" and aborts the rest of the
// notification setup.
func (h *UserInfoStubHandler) HeyGetNotifications(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &NotificationsData{Activities: []string{}}
	SendResponse(w, r, resp, h.Logger)
}

func (h *UserInfoStubHandler) EmptyOK(w http.ResponseWriter, r *http.Request) {
	h.emptyOK(w, r)
}

func (h *UserInfoStubHandler) emptyOK(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}
