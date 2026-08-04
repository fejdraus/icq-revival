package handlers

import (
	"log/slog"
	"net/http"
)

// ServiceStubHandler serves the /service/* endpoints that manage third-party
// service linking (Google Talk, Facebook), none of which this server federates.
type ServiceStubHandler struct {
	Logger *slog.Logger
}

// statusNoSuchService is the envelope status the Web AIM client accepts as
// "this account has no such linked service". Its getAttributes callback treats
// 601 as an expected outcome and returns early; any other status sends it into
// the success branch, where it dereferences response.data.serviceName and marks
// the service associated. A 404 therefore both crashes the callback and, if it
// did not, would advertise a Google Talk link that does not exist.
const statusNoSuchService = 601

// GetAttributes reports that the requested third-party service is not linked.
func (h *ServiceStubHandler) GetAttributes(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = statusNoSuchService
	resp.Response.StatusText = "Service not available"
	SendResponse(w, r, resp, h.Logger)
}
