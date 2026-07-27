package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// rateLimitStatusCode is the Web AIM API envelope code for a rate-limited
// request. The AIM web client swallows 430 on the IM path so that the rateLimit
// event owns the user-facing message instead of a generic send failure alert.
const rateLimitStatusCode = 430

// minRetryAfter floors the Retry-After hint sent with a rate-limited response.
// The computed wait can round down to nothing when a class is barely over its
// limit, and a hint of zero invites an immediate retry.
const minRetryAfter = 1 * time.Second

// SessionHandlerFunc is the session-aware handler shape that
// AuthMiddleware.RequireSession invokes once it has resolved an aimsid.
type SessionHandlerFunc = func(http.ResponseWriter, *http.Request, *state.WebAPISession)

// RateLimitMiddleware enforces OSCAR rate limits on Web API routes that reach a
// food group.
//
// Such routes are limited by OSCAR itself: OSCAR charges the session's shared
// per-rate-class budget, the same budget a native OSCAR or TOC client spends, so
// a user cannot dodge a limit by switching transports. Routes that reach no food
// group are not limited here; edge rate limiting (a reverse proxy keyed by client
// IP) is expected to cover the unauthenticated login/asset endpoints and the
// authenticated bookkeeping ones.
//
// It lives alongside the handlers (rather than in the middleware package) so that
// its rejection can be encoded through the same SendResponse path the handlers
// use, honoring the request's JSON/JSONP/XML/AMF format.
type RateLimitMiddleware struct {
	snacRateLimits wire.SNACRateLimits
	// alertRateClassID is the only rate class that pushes a rateLimit event; see
	// syncRateAlert. Zero when the SNAC table has no mapping for sending an IM,
	// which disables the push rather than indexing a rate class that isn't there.
	alertRateClassID wire.RateLimitClassID
	logger           *slog.Logger
}

// NewRateLimitMiddleware creates a RateLimitMiddleware. snacRateLimits is the
// same SNAC-to-rate-class mapping the OSCAR and TOC servers use.
func NewRateLimitMiddleware(snacRateLimits wire.SNACRateLimits, logger *slog.Logger) *RateLimitMiddleware {
	alertRateClassID, ok := snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		logger.Error("no rate class maps to sending an IM, rate limit events are disabled")
	}

	return &RateLimitMiddleware{
		snacRateLimits:   snacRateLimits,
		alertRateClassID: alertRateClassID,
		logger:           logger,
	}
}

// OSCAR returns middleware that charges one unit against the OSCAR rate class
// mapped to (foodGroup, subGroup) before invoking the wrapped handler. It is the
// HTTP counterpart of the TOC server's per-command rate check.
//
// A SNAC with no rate class mapping is allowed through, since refusing traffic
// because the server's own table is incomplete would be worse than not limiting
// it.
func (l *RateLimitMiddleware) OSCAR(foodGroup uint16, subGroup uint16) func(SessionHandlerFunc) SessionHandlerFunc {
	return func(next SessionHandlerFunc) SessionHandlerFunc {
		return func(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
			ctx := r.Context()

			rateClassID, ok := l.snacRateLimits.RateClassLookup(foodGroup, subGroup)
			if !ok {
				l.logger.ErrorContext(ctx, "rate limit not found, allowing request through",
					"foodgroup", wire.FoodGroupName(foodGroup),
					"subgroup", wire.SubGroupName(foodGroup, subGroup))
				next(w, r, session)
				return
			}

			sess := session.OSCARSession.Session()
			status := sess.EvaluateRateLimit(time.Now(), rateClassID)
			l.syncRateAlert(session, rateClassID, status)

			// Disconnect is rejected alongside Limited: EvaluateRateLimit has
			// already closed the account's OSCAR session by the time it returns,
			// so there is nothing left for the handler to act on. That close also
			// invalidates the aimsid (GetSession stops resolving a session whose
			// OSCAR instance is closed), so every subsequent request is turned
			// away at RequireSession rather than reaching here again.
			if status == wire.RateLimitStatusLimited || status == wire.RateLimitStatusDisconnect {
				l.logger.DebugContext(ctx, "(webapi) rate limit exceeded, dropping request",
					"foodgroup", wire.FoodGroupName(foodGroup),
					"subgroup", wire.SubGroupName(foodGroup, subGroup),
					"status", rateLimitStatusName(status))

				// A disconnected session has no aimsid left to retry with, so
				// there is no wait to advertise.
				var retryAfter time.Duration
				if status == wire.RateLimitStatusLimited {
					retryAfter = retryAfterFor(sess.RateLimitStates()[rateClassID-1])
				}
				l.sendRateLimited(w, r, retryAfter)
				return
			}

			next(w, r, session)
		}
	}
}

// RecoverOnPoll re-evaluates rate limit recovery before serving a long poll and
// pushes the "clear" that dismisses the client's alert once it recovers.
//
// OSCAR only recomputes rate limit status on a charged request (see OSCAR), so a
// session that trips the limit and then goes idle would never learn it recovered,
// and the client's alert is sticky until a "clear" arrives. fetchEvents is polled
// continuously, so recovering here surfaces the clear without the user sending
// anything; the push happens before next() so it rides out on this poll.
//
// Only a clear is pushed. A poll is not a request the user made, so it must not
// raise an alert: the budget is account-wide, and syncing an idle tab up to a
// limit another tab tripped would tell a user doing nothing to stop chatting. The
// limit reaches a client on the request it actually rejects, in OSCAR.
func (l *RateLimitMiddleware) RecoverOnPoll(next SessionHandlerFunc) SessionHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, session *state.WebAPISession) {
		if l.alertRateClassID == 0 {
			next(w, r, session)
			return
		}

		sess := session.OSCARSession.Session()
		sess.RecoverRateLimits(time.Now())
		if status := sess.RateLimitStates()[l.alertRateClassID-1].CurrentStatus; status == wire.RateLimitStatusClear {
			l.syncRateAlert(session, l.alertRateClassID, status)
		}

		next(w, r, session)
	}
}

// syncRateAlert notifies the client that its rate limit status changed so it can
// show (or dismiss) the rate limit alert. The disconnect push is best-effort:
// EvaluateRateLimit closes the session before the queue drains.
//
// Only alertRateClassID pushes. The client throws away the class id the event
// carries and feeds the status into a single alert rendered inside a
// conversation window ("You have been rate limited. Wait for a few moments until
// you can chat again."), so the one class it can truthfully describe is the one
// sending an IM spends. Pushing for the others would pop a chat alert for a
// buddy list edit while IMs still work, and let a "clear" on an unrelated class
// dismiss an alert the IM class raised. They stay enforced, silently.
func (l *RateLimitMiddleware) syncRateAlert(session *state.WebAPISession, classID wire.RateLimitClassID, status wire.RateLimitStatus) {
	if classID != l.alertRateClassID {
		return
	}
	name := rateLimitStatusName(status)
	if name == "" {
		return
	}
	if !session.ObserveRateAlert(status) {
		return
	}

	session.EventQueue.Push(types.EventTypeRateLimit, types.RateLimitEvent{
		Classes: []types.RateLimitClass{
			{
				ID:     int(classID),
				Status: name,
			},
		},
	})
}

// retryAfterFor returns how long the client must wait for its next request on
// this class to clear the limit.
//
// OSCAR's limiter has no fixed window: it tracks a moving average of the gap
// between requests, and a request lifts the limit only once that average climbs
// back to ClearLevel. Inverting CheckRateLimit's update for the elapsed time that
// lands the new average exactly on ClearLevel gives
//
//	elapsed = ClearLevel*WindowSize - CurrentLevel*(WindowSize-1)
//
// A flat hint cannot work here, because a rejected request is still charged: a
// client retrying on a fixed interval drives the average toward that interval, so
// any hint below the class's ClearLevel holds the average just under the bar and
// the client stays limited forever. The production ICBM class clears at 5100ms,
// which a 5s hint would do exactly.
func retryAfterFor(rcs state.RateClassState) time.Duration {
	neededMs := int64(rcs.ClearLevel)*int64(rcs.WindowSize) - int64(rcs.CurrentLevel)*int64(rcs.WindowSize-1)

	// Retry-After carries whole seconds, so round up: a hint that is short by a
	// fraction of a second reproduces the same never-clears loop. A class barely
	// over its limit can compute to no wait at all, hence the floor.
	return max(time.Duration((neededMs+999)/1000)*time.Second, minRetryAfter)
}

// rateLimitStatusName maps an OSCAR rate limit status onto the status string the
// web client switches on. It returns "" for a status the client does not know.
func rateLimitStatusName(status wire.RateLimitStatus) string {
	switch status {
	case wire.RateLimitStatusClear:
		return "clear"
	case wire.RateLimitStatusAlert:
		return "warn"
	case wire.RateLimitStatusLimited:
		return "limit"
	case wire.RateLimitStatusDisconnect:
		return "disconnect"
	default:
		return ""
	}
}

// sendRateLimited writes a rate limit rejection. The transport status is 200 and
// the rejection lives entirely in the Web AIM API envelope's own rate limit code.
//
// The transport status is deliberately not 429: the AIM client's WIM request layer
// (XhrManager) and its Fetcher only parse the response body on a 2xx. A non-2xx is
// routed to their error handlers, which synthesize a generic "request failed"
// result and never look at the body, so the envelope's 430 — which the client
// swallows on the IM path in favor of the rateLimit event — would go unread and the
// user would see a generic send failure instead.
//
// The body is encoded via SendResponse, so it honors the request's format
// (JSON/JSONP/XML/AMF) and echoes the request id into response.requestId — which
// the JSONP fallback needs to correlate the reply, or its UI hangs — exactly as a
// normal handler response would.
//
// A retryAfter of zero sends no Retry-After header, for the rejections that have
// nothing to retry.
func (l *RateLimitMiddleware) sendRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = rateLimitStatusCode
	resp.Response.StatusText = "rate limit exceeded"

	SendResponse(w, r, resp, l.logger)
}
