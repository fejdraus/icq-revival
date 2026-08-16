package kerberos

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestKerberosLoginHandler(t *testing.T) {
	tests := []struct {
		name               string
		listeners          []config.ListenerGroup
		request            wire.SNACMessage
		response           wire.SNACMessage
		responseErr        error
		expectLogin        bool
		expectSNACResponse bool
		wantStatus         int
	}{
		{
			name: "successful login with single listener",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: ":1088",
					BOSAdvertisedHostSSL:  "localhost:5190",
				},
			},
			request: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginRequest,
				},
				Body: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
					RequestID: 4321,
				},
			},
			response: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginSuccessResponse,
				},
				Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
					RequestID: 4321,
				},
			},
			expectLogin:        true,
			expectSNACResponse: true,
			wantStatus:         http.StatusOK,
		},
		{
			name: "successful login with multiple listeners",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: ":1088",
					BOSAdvertisedHostSSL:  "localhost:5190",
				},
				{
					KerberosListenAddress: ":1089",
					BOSAdvertisedHostSSL:  "localhost:5191",
				},
			},
			request: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginRequest,
				},
				Body: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
					RequestID: 4321,
				},
			},
			response: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginSuccessResponse,
				},
				Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
					RequestID: 4321,
				},
			},
			expectLogin:        true,
			expectSNACResponse: true,
			wantStatus:         http.StatusOK,
		},
		{
			name: "successful login with three listeners",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: ":1088",
					BOSAdvertisedHostSSL:  "localhost:5190",
				},
				{
					KerberosListenAddress: ":1089",
					BOSAdvertisedHostSSL:  "localhost:5191",
				},
				{
					KerberosListenAddress: ":1090",
					BOSAdvertisedHostSSL:  "localhost:5192",
				},
			},
			request: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginRequest,
				},
				Body: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
					RequestID: 4321,
				},
			},
			response: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginSuccessResponse,
				},
				Body: wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{
					RequestID: 4321,
				},
			},
			expectLogin:        true,
			expectSNACResponse: true,
			wantStatus:         http.StatusOK,
		},
		{
			name: "no kerberos listeners defined - server exits cleanly",
			listeners: []config.ListenerGroup{
				{
					BOSAdvertisedHostSSL: "localhost:5192",
				},
			},
			request:            wire.SNACMessage{},
			response:           wire.SNACMessage{},
			responseErr:        nil,
			expectLogin:        false,
			expectSNACResponse: false,
			wantStatus:         0, // No server to test against
		},
		{
			name: "invalid request SNAC type",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: ":1088",
					BOSAdvertisedHostSSL:  "localhost:5190",
				},
			},
			request: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
					RequestID: 4321,
				},
			},
			expectLogin:        false,
			expectSNACResponse: false,
			wantStatus:         http.StatusBadRequest,
		},
		{
			name: "login runtime error",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: ":1088",
					BOSAdvertisedHostSSL:  "localhost:5190",
				},
			},
			request: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Kerberos,
					SubGroup:  wire.KerberosLoginRequest,
				},
				Body: wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
					RequestID: 4321,
				},
			},
			response:           wire.SNACMessage{},
			responseErr:        io.EOF,
			expectLogin:        true,
			expectSNACResponse: false,
			wantStatus:         http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))

			var srv *Server
			if len(tt.listeners) > 0 {
				mockAuth := newMockAuthService(t)
				if tt.expectLogin {
					mockAuth.EXPECT().
						KerberosLogin(mock.Anything, tt.request.Body, mock.Anything).
						Return(tt.response, tt.responseErr)
				}
				srv = NewKerberosServer(tt.listeners, log, mockAuth)
			} else {
				// For no listeners case, we don't need auth service or request data
				srv = NewKerberosServer(tt.listeners, log, nil)
			}

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				assert.NoError(t, srv.ListenAndServe())
			}()

			// Wait for server to be ready by checking if ports are listening
			for i := 0; i < len(tt.listeners); i++ {
				if tt.listeners[i].KerberosListenAddress == "" {
					continue
				}
				maxRetries := 10
				backoff := 5 * time.Millisecond

				for attempt := 0; attempt < maxRetries; attempt++ {
					conn, err := net.Dial("tcp", "localhost"+tt.listeners[i].KerberosListenAddress)
					if err == nil {
						_ = conn.Close()
						break
					}
					if attempt == maxRetries-1 {
						t.Fatalf("Server not ready after %d attempts: %v", maxRetries, err)
					}
					time.Sleep(backoff)
					backoff *= 2
				}
			}

			// Test against all listeners
			for i, listener := range tt.listeners {
				if listener.KerberosListenAddress == "" {
					continue
				}

				b := &bytes.Buffer{}
				assert.NoError(t, wire.MarshalBE(tt.request, b))

				resp, err := http.Post(fmt.Sprintf("http://localhost:%s", listener.KerberosListenAddress[1:]), "application/x-snac", b)
				assert.NoError(t, err)
				defer func() { _ = resp.Body.Close() }()

				assert.Equal(t, tt.wantStatus, resp.StatusCode, "listener %d at %s", i, listener.KerberosListenAddress)

				if tt.expectSNACResponse {
					respBytes, _ := io.ReadAll(resp.Body)
					reader := bytes.NewReader(respBytes)
					haveFrame := wire.SNACFrame{}
					assert.NoError(t, wire.UnmarshalBE(&haveFrame, reader))
					assert.Equal(t, tt.response.Frame, haveFrame)
					haveBody := wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse{}
					assert.NoError(t, wire.UnmarshalBE(&haveBody, reader))
					assert.Equal(t, tt.response.Body, haveBody)
					assert.Equal(t, "application/x-snac", resp.Header.Get("Content-Type"))
				} else {
					assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
				}
			}

			assert.NoError(t, srv.Shutdown(context.Background()))
			wg.Wait()
		})
	}
}

func TestNewKerberosServer_ServesSSLGroupsOnly(t *testing.T) {
	tests := []struct {
		name      string
		listeners []config.ListenerGroup
		wantAddrs []string
	}{
		{
			name: "SSL group with a kerberos address binds its port once",
			listeners: []config.ListenerGroup{
				{
					KerberosListenAddress: "127.0.0.1:1088",
					BOSAdvertisedHostSSL:  "localhost:5193",
				},
			},
			wantAddrs: []string{"127.0.0.1:1088"},
		},
		{
			name: "plaintext-only group is not served",
			listeners: []config.ListenerGroup{
				{KerberosListenAddress: "127.0.0.1:1088"},
			},
			wantAddrs: []string{},
		},
		{
			name: "SSL group without a kerberos address is skipped rather than bound to :80",
			listeners: []config.ListenerGroup{
				{KerberosListenAddress: "", BOSAdvertisedHostSSL: "localhost:5193"},
				{KerberosListenAddress: "127.0.0.1:1089", BOSAdvertisedHostSSL: "localhost:5193"},
			},
			wantAddrs: []string{"127.0.0.1:1089"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewKerberosServer(tt.listeners, slog.Default(), newMockAuthService(t))

			haveAddrs := make([]string, 0, len(srv.servers))
			for _, s := range srv.servers {
				haveAddrs = append(haveAddrs, s.Addr)
			}

			assert.Equal(t, tt.wantAddrs, haveAddrs)
		})
	}
}
