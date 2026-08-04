package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// BaseResponse is the standard response envelope for all Web API responses.
// It supports both JSON and XML marshaling.
type BaseResponse struct {
	Response ResponseBody `json:"response"`
}

// MarshalXML renders the envelope as the Web API's flat <response> root, where
// JSON nests the same body under a "response" key. Reconciling the two shapes
// here is what lets one struct describe a response in both formats.
func (b BaseResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.EncodeElement(b.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// ResponseBody contains the status and data for API responses.
type ResponseBody struct {
	StatusCode int    `json:"statusCode" xml:"statusCode"`
	StatusText string `json:"statusText" xml:"statusText"`
	RequestID  string `json:"requestId,omitempty" xml:"requestId,omitempty"`
	// Data is never omitted. Every Web API method sends a data element even when
	// it carries no payload, and the client dereferences response.data on any
	// success; SendResponse substitutes an empty object when a handler sets none.
	Data interface{} `json:"data" xml:"data"`
}

// ErrorResponse represents an error response with proper XML/JSON support.
type ErrorResponse struct {
	Response struct {
		StatusCode int    `json:"statusCode" xml:"statusCode"`
		StatusText string `json:"statusText" xml:"statusText"`
		// Data carries an empty object for the same reason the JSONP error path
		// sends one: a client callback that reaches response.data on a failure
		// throws a TypeError when it is absent.
		Data interface{} `json:"data" xml:"data"`
	} `json:"response"`
}

// MarshalXML renders the error envelope with the same flat root as BaseResponse.
func (e ErrorResponse) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	return enc.EncodeElement(e.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// newErrorResponse builds the error envelope every format shares.
func newErrorResponse(statusCode int, message string) ErrorResponse {
	resp := ErrorResponse{}
	resp.Response.StatusCode = statusCode
	resp.Response.StatusText = message
	resp.Response.Data = struct{}{}
	return resp
}

// requestIDFromRequest returns the Web AIM client request correlation id from the
// "r" query parameter. JSONP callbacks require this echoed in response.requestId.
func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.URL.Query().Get("r")
}

// normalizeEnvelope fills in the envelope fields a handler does not set itself:
// the request correlation id, and an empty data object for a response that
// carries no payload. Both are things every encoder needs and none can infer —
// and encoding/xml has no way to render a nil data at all.
func normalizeEnvelope(r *http.Request, data interface{}) interface{} {
	br, ok := data.(BaseResponse)
	if !ok {
		return data
	}
	if br.Response.RequestID == "" {
		br.Response.RequestID = requestIDFromRequest(r)
	}
	if br.Response.Data == nil {
		br.Response.Data = struct{}{}
	}
	return br
}

// SendResponse sends a response in the requested format (JSON, JSONP, XML, or AMF).
// This is the centralized function that all handlers should use for responses.
func SendResponse(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	data = normalizeEnvelope(r, data)

	// Check for format parameter (f for format or callback for JSONP)
	// First check URL query parameters
	format := strings.ToLower(r.URL.Query().Get("f"))
	callback := jsonpCallback(r)

	// If format not in URL query, check form values (for POST requests)
	if format == "" && r.Method == "POST" {
		_ = r.ParseForm()
		format = strings.ToLower(r.FormValue("f"))
		if callback == "" {
			callback = jsonpCallback(r)
		}
	}

	// Check for AMF format first
	if format == "amf" || format == "amf3" {
		sendAMF(w, r, data, logger)
		return
	}

	// Check Accept header for AMF
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/x-amf") ||
		strings.Contains(accept, "application/amf") {
		sendAMF(w, r, data, logger)
		return
	}

	// If callback is provided, it's JSONP
	if callback != "" {
		sendJSONP(w, r, callback, data, logger)
		return
	}

	// Check for XML format
	if format == "xml" {
		sendXML(w, data, logger)
		return
	}

	// Default to JSON
	sendJSON(w, data, logger)
}

// SendError sends an error response in the format the client asked for.
//
// When the client requested JSONP, the error must be delivered as an executable
// callback: a bare JSON body inside a <script> tag is a syntax error, which the
// Web AIM client reports as the generic "Failed to load script tag, probably
// malformed JS at that url" instead of the real statusText.
func SendError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	if callback := jsonpCallback(r); callback != "" && isValidCallback(callback) {
		sendJSONPError(w, r, callback, statusCode, message)
		return
	}

	// Try to detect format from Content-Type header if already set
	contentType := w.Header().Get("Content-Type")

	if strings.Contains(contentType, "amf") {
		sendAMFError(w, r, statusCode, message, nil)
	} else if strings.Contains(contentType, "xml") {
		sendXMLError(w, statusCode, message)
	} else {
		sendJSONError(w, statusCode, message)
	}
}

// sendJSONPError writes an error envelope wrapped in the client's JSONP callback.
//
// The HTTP status is deliberately left at 200: browsers do not execute the body
// of a <script> tag that came back with a 4xx or 5xx, so a status-carrying JSONP
// error never reaches the callback at all. The real status travels in the
// envelope, which is where the Web AIM client reads it from regardless.
func sendJSONPError(w http.ResponseWriter, r *http.Request, callback string, statusCode int, message string) {
	envelope := map[string]any{
		"statusCode": statusCode,
		"statusText": message,
		// Callbacks that reach response.data on a failure throw a TypeError when
		// it is absent, which aborts whatever the client was doing mid-startup.
		// Its XHR path fabricates an empty data for transport failures; JSONP
		// delivers the envelope verbatim, so the empty data has to come from here.
		"data": map[string]any{},
	}
	// The client indexes JSONP replies by response.requestId and discards any
	// reply that lacks one ("Request id is missing from the server response"),
	// leaving the request pending until it times out.
	if id := requestIDFromRequest(r); id != "" {
		envelope["requestId"] = id
	}

	body, err := json.Marshal(map[string]any{"response": envelope})
	if err != nil {
		sendJSONError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(callback))
	_, _ = w.Write([]byte("("))
	_, _ = w.Write(body)
	_, _ = w.Write([]byte(");"))
}

// sendJSONError sends a JSON error response.
func sendJSONError(w http.ResponseWriter, statusCode int, message string) {
	resp := newErrorResponse(statusCode, message)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// sendXMLError sends an XML error response.
func sendXMLError(w http.ResponseWriter, statusCode int, message string) {
	resp := newErrorResponse(statusCode, message)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(statusCode)

	// Write XML declaration and marshal the response
	xmlData, err := xml.Marshal(resp)
	if err != nil {
		// Fall back to simple text response
		http.Error(w, message, statusCode)
		return
	}

	xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)
	_, _ = w.Write([]byte(xmlOutput))
}

// sendJSON sends a JSON response.
func sendJSON(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to encode JSON response", "err", err.Error())
		}
		return
	}
	if logger != nil {
		logger.Debug("JSON response", "body", string(body))
	}
	if _, err := w.Write(body); err != nil && logger != nil {
		logger.Error("failed to write JSON response", "err", err.Error())
	}
}

// sendXML sends an XML response.
func sendXML(w http.ResponseWriter, data interface{}, logger *slog.Logger) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")

	// Every payload is a struct whose xml tags name its elements, and the
	// envelope's MarshalXML renders the flat <response> root the Web API uses.
	xmlData, err := xml.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal XML response", "err", err.Error())
		}
		sendXMLError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Write XML declaration and data
	xmlOutput := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>%s`, xmlData)

	// Set content length for proper response handling
	w.Header().Set("Content-Length", strconv.Itoa(len(xmlOutput)))
	_, _ = w.Write([]byte(xmlOutput))
}

// jsonpCallback returns the JSONP callback name from the request.
// Web AIM clients use the "c" query parameter; other callers may use "callback".
func jsonpCallback(r *http.Request) string {
	if r == nil {
		return ""
	}
	if callback := r.URL.Query().Get("c"); callback != "" {
		return callback
	}
	return r.URL.Query().Get("callback")
}

// sendJSONP sends a JSONP response with the specified callback.
func sendJSONP(w http.ResponseWriter, r *http.Request, callback string, data interface{}, logger *slog.Logger) {
	// Validate callback to prevent XSS. This is the one error here that cannot be
	// delivered as JSONP: there is no callback name safe to write.
	if !isValidCallback(callback) {
		sendJSONError(w, http.StatusBadRequest, "invalid callback parameter")
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		if logger != nil {
			logger.Error("failed to marshal response", "err", err.Error())
		}
		// The client is on the <script> transport, so the error has to be
		// executable JS for it to see anything but a load failure.
		sendJSONPError(w, r, callback, http.StatusInternalServerError, "internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(callback))
	_, _ = w.Write([]byte("("))
	_, _ = w.Write(jsonData)
	_, _ = w.Write([]byte(");"))
}

// isValidCallback validates a JSONP callback name to prevent XSS.
func isValidCallback(callback string) bool {
	if len(callback) == 0 || len(callback) > 100 {
		return false
	}

	// Allow alphanumeric, underscore, dollar sign, and dot (for namespace)
	for _, r := range callback {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' && r != '$' && r != '.' {
			return false
		}
	}

	return true
}

// sendAMF sends an AMF response
func sendAMF(w http.ResponseWriter, r *http.Request, data interface{}, logger *slog.Logger) {
	encoder := NewAMFEncoder(logger)
	version := DetectAMFVersion(r)

	amfData, err := encoder.EncodeAMF(data, version)
	if err != nil {
		if logger != nil {
			logger.Error("failed to encode AMF response",
				"err", err.Error(),
				"version", version,
				"dataType", fmt.Sprintf("%T", data))
		}
		// Fall back to JSON error
		sendJSONError(w, http.StatusInternalServerError, "AMF encoding failed")
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))

	// Debug logging if enabled
	if logger != nil && logger.Enabled(context.TODO(), slog.LevelDebug) {
		hexPreview := ""
		if len(amfData) > 0 {
			previewLen := len(amfData)
			if previewLen > 64 {
				previewLen = 64
			}
			hexPreview = hex.EncodeToString(amfData[:previewLen])
		}

		logger.Debug("sending AMF response",
			"version", version,
			"size", len(amfData),
			"path", r.URL.Path,
			"hexPreview", hexPreview)
	}

	if _, err := w.Write(amfData); err != nil {
		if logger != nil {
			logger.Error("failed to write AMF response",
				"err", err.Error())
		}
	}
}

// sendAMFError sends an AMF error response
func sendAMFError(w http.ResponseWriter, r *http.Request, statusCode int, message string, logger *slog.Logger) {
	errorResp := newErrorResponse(statusCode, message)

	encoder := NewAMFEncoder(logger)
	version := DetectAMFVersion(r)

	amfData, err := encoder.EncodeAMF(errorResp, version)
	if err != nil {
		// If AMF encoding fails, fall back to JSON error
		sendJSONError(w, statusCode, message)
		return
	}

	w.Header().Set("Content-Type", "application/x-amf")
	w.Header().Set("Content-Length", strconv.Itoa(len(amfData)))
	w.WriteHeader(statusCode)
	_, _ = w.Write(amfData)
}
