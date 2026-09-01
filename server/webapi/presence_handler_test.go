package webapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// onlineUserInfoReply builds a locate UserInfoReply for an online user,
// optionally marking them idle by the given number of minutes (0 = not idle).
func onlineUserInfoReply(screenName string, idleMinutes uint16) wire.SNACMessage {
	info := wire.TLVUserInfo{ScreenName: screenName}
	if idleMinutes > 0 {
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoIdleTime, idleMinutes))
	}
	return wire.SNACMessage{
		Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{TLVUserInfo: info},
	}
}

// screenNameMatcher matches a UserInfoQuery request body by its target screen name.
func screenNameMatcher(screenName string) any {
	return mock.MatchedBy(func(b wire.SNAC_0x02_0x05_LocateUserInfoQuery) bool {
		return b.ScreenName == screenName
	})
}

func TestPresenceHandler_GetPresence(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*mockFeedbagService, *mockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_BuddyList",
			queryParams: "bl=1",
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				// Return feedbag with a group and buddy
				fr.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
					Return(wire.SNACMessage{
						Body: wire.SNAC_0x13_0x06_FeedbagReply{
							Items: []wire.FeedbagItem{
								{ItemID: 0, ClassID: wire.FeedbagClassIdGroup, Name: "Friends", GroupID: 1},
								{ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "buddy1", GroupID: 1},
							},
						},
					}, nil)
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("buddy1")).
					Return(onlineUserInfoReply("buddy1", 0), nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"groups"`)
				assert.Contains(t, body, `"Friends"`)
				assert.Contains(t, body, `"buddy1"`)
				assert.Contains(t, body, `"online"`)
			},
		},
		{
			name:        "Success_TargetUsers",
			queryParams: "t=user1,user2",
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user1")).
					Return(onlineUserInfoReply("user1", 0), nil)
				// user2 is idle for 7 minutes.
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("user2")).
					Return(onlineUserInfoReply("user2", 7), nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"users"`)
				assert.Contains(t, body, `"user1"`)
				assert.Contains(t, body, `"user2"`)
				assert.Contains(t, body, `"idle"`)
			},
		},
		{
			name:        "Success_BlockedOrOfflineUser",
			queryParams: "t=blockeduser",
			setupMocks: func(fr *mockFeedbagService, ls *mockLocateService) {
				// A blocked or offline user comes back as a locate error.
				ls.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("blockeduser")).
					Return(wire.SNACMessage{Body: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}}, nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"blockeduser"`)
				assert.Contains(t, body, `"offline"`)
			},
		},
		{
			name:               "Success_EmptyRequest",
			queryParams:        "",
			setupMocks:         func(fr *mockFeedbagService, ls *mockLocateService) {},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:        "Error_TooManyTargets",
			queryParams: "t=u1,u2,u3,u4,u5,u6,u7,u8,u9,u10,u11",
			// No UserInfoQuery should be issued; the request is rejected up front.
			setupMocks:         func(fr *mockFeedbagService, ls *mockLocateService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "too many screen names requested")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feedbagService := newMockFeedbagService(t)
			locateService := newMockLocateService(t)

			oscarInstance := state.NewSession().AddInstance()
			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				FeedbagService: feedbagService,
				LocateService:  locateService,
				Logger:         slog.Default(),
			}

			tt.setupMocks(feedbagService, locateService)

			// Presence payloads carry the viewer's alias, so GetPresence reads the
			// feedbag. Registered last so a case's own Query stub takes precedence.
			feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
				Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

			reqURL := "/presence/get?aimsid=" + aimsid
			if tt.queryParams != "" {
				reqURL += "&" + tt.queryParams
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}
		})
	}
}

// TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly verifies that
// the icon is published only for an online, non-blocking user, and that an
// offline or blocking user is never even looked up — so neither their icon nor
// its hash leaks to a caller they are invisible to.
func TestPresenceHandler_GetPresence_PublishesIconForOnlineBuddiesOnly(t *testing.T) {
	ctx := context.Background()

	feedbagService := newMockFeedbagService(t)
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{}}, nil).Maybe()

	locateService := newMockLocateService(t)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("onlineuser")).
		Return(onlineUserInfoReply("onlineuser", 0), nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("offlineuser")).
		Return(wire.SNACMessage{Body: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}}, nil)

	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, state.NewIdentScreenName("onlineuser")).
		Return(bartID([]byte{0xab, 0xcd}), nil).Once()

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	sess, err := sessionMgr.GetSession(ctx, aimsid)
	require.NoError(t, err)
	sess.BaseURL = "http://api.example.com"

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		IconSource:     BuddyIconSource{IconRetriever: iconRetriever, Logger: slog.Default()},
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&t=onlineuser,offlineuser", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			Data struct {
				Users []struct {
					AimID     string `json:"aimId"`
					State     string `json:"state"`
					BuddyIcon string `json:"buddyIcon"`
				} `json:"users"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))

	icons := map[string]string{}
	states := map[string]string{}
	for _, u := range got.Response.Data.Users {
		icons[u.AimID] = u.BuddyIcon
		states[u.AimID] = u.State
	}

	assert.Equal(t, "online", states["onlineuser"])
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=onlineuser&type=buddyIcon&bartId=abcd",
		icons["onlineuser"])

	assert.Equal(t, "offline", states["offlineuser"])
	assert.Empty(t, icons["offlineuser"])
	iconRetriever.AssertNotCalled(t, "BuddyIconMetadata", mock.Anything, state.NewIdentScreenName("offlineuser"))
}

// TestPresenceHandler_GetPresence_BuddyListGrouping verifies that bl=1 places
// each buddy under its own group using realistic feedbag data, where group rows
// carry ItemID 0 and a distinct nonzero GroupID, and buddy rows reference those
// GroupIDs. This is the shape the OSCAR feedbag actually stores.
func TestPresenceHandler_GetPresence_BuddyListGrouping(t *testing.T) {
	feedbagService := newMockFeedbagService(t)
	locateService := newMockLocateService(t)

	items := []wire.FeedbagItem{
		// Root order group: ItemID 0, GroupID 0, empty name — not a real buddy group.
		{ItemID: 0, GroupID: 0, ClassID: wire.FeedbagClassIdGroup, Name: ""},
		// Named groups: ItemID 0, distinct nonzero GroupIDs.
		{ItemID: 0, GroupID: 10, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"},
		{ItemID: 0, GroupID: 20, ClassID: wire.FeedbagClassIdGroup, Name: "Work"},
		// Buddies reference their group's GroupID.
		{ItemID: 101, GroupID: 10, ClassID: wire.FeedbagClassIdBuddy, Name: "alice"},
		{ItemID: 201, GroupID: 20, ClassID: wire.FeedbagClassIdBuddy, Name: "bob"},
	}
	feedbagService.EXPECT().Query(mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{Items: items}}, nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("alice")).
		Return(onlineUserInfoReply("alice", 0), nil)
	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("bob")).
		Return(onlineUserInfoReply("bob", 0), nil)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)
	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		FeedbagService: feedbagService,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid="+aimsid+"&bl=1", nil)
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var parsed struct {
		Response struct {
			Data struct {
				Groups []struct {
					Name    string `json:"name"`
					Buddies []struct {
						AimID string `json:"aimId"`
					} `json:"buddies"`
				} `json:"groups"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &parsed))

	// Build name -> set of buddy aimIds.
	byGroup := map[string][]string{}
	for _, g := range parsed.Response.Data.Groups {
		for _, b := range g.Buddies {
			byGroup[g.Name] = append(byGroup[g.Name], b.AimID)
		}
	}

	// Exactly the two named groups appear; the root group is excluded.
	assert.Len(t, parsed.Response.Data.Groups, 2)
	assert.Equal(t, []string{"alice"}, byGroup["Friends"])
	assert.Equal(t, []string{"bob"}, byGroup["Work"])
}

func TestPresenceHandler_GetPresence_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: NewSessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestPresenceHandler_GetPresence_SessionNotFound(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: NewSessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/get?aimsid=nonexistent", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetPresence).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
}

func TestPresenceHandler_SetState_MissingAimsid(t *testing.T) {
	handler := &PresenceHandler{
		SessionManager: NewSessionManager(),
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestPresenceHandler_SetState_InvalidState(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=bogus", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid state parameter")
}

func TestPresenceHandler_SetState_EmitsMyInfoEvent(t *testing.T) {
	// The AIM client re-renders its own status badge only from "myInfo" events,
	// so setState must queue one on the user's own session for the change to be
	// visible in their UI.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	broadcaster := newMockBuddyBroadcaster(t)
	broadcaster.EXPECT().BroadcastBuddyArrived(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := &PresenceHandler{
		SessionManager:   sessionMgr,
		BuddyBroadcaster: broadcaster,
		Logger:           slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away&awayMsg=brb", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	session, err := sessionMgr.GetSession(context.Background(), aimsid)
	assert.NoError(t, err)

	myInfo := queuedMyInfo(session)
	assert.NotNil(t, myInfo, "expected a myInfo event to be queued")
	assert.Equal(t, "away", myInfo.State)
	assert.Equal(t, "brb", myInfo.AwayMsg)
	assert.Equal(t, "testuser", myInfo.AimID)
}

func TestPresenceHandler_SetState_MyInfoNormalizesAimID(t *testing.T) {
	// The client shallow-merges myInfo onto the shared user object, so aimId must
	// be the normalized id while displayId and friendly keep the user's own
	// casing and spacing.
	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("Mike Kelly", oscarInstance)

	broadcaster := newMockBuddyBroadcaster(t)
	broadcaster.EXPECT().BroadcastBuddyArrived(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := &PresenceHandler{
		SessionManager:   sessionMgr,
		BuddyBroadcaster: broadcaster,
		Logger:           slog.Default(),
	}

	req, err := http.NewRequest("GET", "/presence/setState?aimsid="+aimsid+"&state=away", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.SetState).ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// The setState response body carries the same identity fields.
	var resp struct {
		Response struct {
			Data map[string]interface{} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "mikekelly", resp.Response.Data["aimId"])
	assert.Equal(t, "Mike Kelly", resp.Response.Data["displayId"])

	session, err := sessionMgr.GetSession(context.Background(), aimsid)
	assert.NoError(t, err)

	myInfo := queuedMyInfo(session)
	require.NotNil(t, myInfo, "expected a myInfo event to be queued")
	assert.Equal(t, "mikekelly", myInfo.AimID)
	assert.Equal(t, "Mike Kelly", myInfo.DisplayID)
	assert.Equal(t, "Mike Kelly", myInfo.Friendly)
}

func TestIsICQScreenName(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		expected   bool
	}{
		{"ICQ_Number", "123456789", true},
		{"AIM_Name", "cooluser", false},
		{"AIM_WithNumbers", "cool123", false},
		{"Empty", "", false},
		{"Single_Digit", "5", true},
		{"Mixed_Chars", "12abc34", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isICQScreenName(tt.screenName))
		})
	}
}

func TestPresenceHandler_Icon(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		expectedStatusCode int
		checkRedirect      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "Redirect_OfflineUser",
			// No aimsid, so there is no OSCAR session to query on behalf of and
			// the target resolves to offline.
			queryParams:        "name=offlineuser",
			expectedStatusCode: http.StatusFound,
			checkRedirect: func(t *testing.T, rr *httptest.ResponseRecorder) {
				location := rr.Header().Get("Location")
				assert.Contains(t, location, "offline")
			},
		},
		{
			name:               "Error_MissingName",
			queryParams:        "",
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &PresenceHandler{
				SessionManager: NewSessionManager(),
				LocateService:  newMockLocateService(t),
				Logger:         slog.Default(),
			}

			reqURL := "/presence/icon"
			if tt.queryParams != "" {
				reqURL += "?" + tt.queryParams
			}
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			handler.Icon(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkRedirect != nil {
				tt.checkRedirect(t, rr)
			}
		})
	}
}

func TestPresenceHandler_SetProfile(t *testing.T) {
	oscarInstance := state.NewSession().AddInstance()

	tests := []struct {
		name               string
		queryParams        string
		setupMocks         func(*mockLocateService)
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_SetProfile",
			queryParams: "profile=Hello+World",
			setupMocks: func(ls *mockLocateService) {
				ls.EXPECT().SetInfo(mock.Anything, oscarInstance, mock.AnythingOfType("wire.SNAC_0x02_0x04_LocateSetInfo")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_ProfileTooLarge",
			queryParams:        "profile=" + strings.Repeat("x", 4097),
			setupMocks:         func(ls *mockLocateService) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "profile too large")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locateService := newMockLocateService(t)

			sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

			handler := &PresenceHandler{
				SessionManager: sessionMgr,
				LocateService:  locateService,
				Logger:         slog.Default(),
			}

			tt.setupMocks(locateService)

			reqURL := "/presence/setProfile?aimsid=" + aimsid + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(handler.SessionManager, handler.SetProfile).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}
		})
	}
}

func TestPresenceHandler_GetProfile(t *testing.T) {
	locateService := newMockLocateService(t)

	oscarInstance := state.NewSession().AddInstance()
	sessionMgr, aimsid := createTestSessionManagerWithOSCAR("testuser", oscarInstance)

	handler := &PresenceHandler{
		SessionManager: sessionMgr,
		LocateService:  locateService,
		Logger:         slog.Default(),
	}

	locateService.EXPECT().UserInfoQuery(mock.Anything, mock.Anything, mock.Anything, screenNameMatcher("testuser")).
		Return(wire.SNACMessage{
			Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
				LocateInfo: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "My profile"),
					},
				},
			},
		}, nil)

	req, err := http.NewRequest("GET", "/presence/getProfile?aimsid="+aimsid, nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(handler.SessionManager, handler.GetProfile).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, `"statusCode":200`)
	assert.Contains(t, body, `"My profile"`)
	assert.Contains(t, body, `"testuser"`)
}

// queuedMyInfo returns the myInfo event the session has queued, if any.
func queuedMyInfo(session *Session) *MyInfo {
	var myInfo *MyInfo
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type == "myInfo" {
			myInfo, _ = event.Data.(*MyInfo)
		}
	}
	return myInfo
}
