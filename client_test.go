package gorestly

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/relychan/goutils"
)

func TestRestyClient(t *testing.T) {
	mockState := createMockServer(t)
	defer mockState.Server.Close()

	t.Setenv("BEARER_TOKEN", mockState.APIKey)
	t.Setenv("BASIC_USER", mockState.Username)
	t.Setenv("BASIC_PASSWORD", mockState.Password)

	testCases := []struct {
		Endpoint   string
		ConfigPath string
	}{
		{
			Endpoint:   "/auth/api-key",
			ConfigPath: "testdata/apiKey.yaml",
		},
		{
			Endpoint:   "/auth/basic",
			ConfigPath: "testdata/basic.yaml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.ConfigPath, func(t *testing.T) {
			config, err := goutils.ReadJSONOrYAMLFile[RestyConfig](tc.ConfigPath)
			if err != nil {
				t.Fatal(err.Error())
			}

			client, err := NewClientFromConfig(*config)
			if err != nil {
				t.Fatal("failed to create client: " + err.Error())
			}
			defer client.Close()

			client.SetBaseURL(mockState.Server.URL)

			resp, err := client.R().Get(tc.Endpoint)
			if err != nil {
				t.Fatal("failed to get: " + err.Error())
			}
			defer resp.Body.Close()

			if resp.StatusCode() != http.StatusOK {
				t.Fatalf("expected HTTP 200, get: %d", resp.StatusCode())
			}
		})
	}
}

type mockServerState struct {
	Server     *httptest.Server
	RetryCount int32
	APIKey     string
	Username   string
	Password   string
}

func createMockServer(t *testing.T) *mockServerState {
	t.Helper()

	state := mockServerState{
		APIKey:   rand.Text(),
		Username: rand.Text(),
		Password: rand.Text(),
	}

	mux := http.NewServeMux()

	writeResponse := func(w http.ResponseWriter, body string) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}

	mux.HandleFunc("/auth/api-key", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodPost:
			apiKey := r.Header.Get("x-hasura-admin-secret")
			expectedValue := "Bearer " + state.APIKey
			if apiKey != expectedValue {
				t.Errorf("invalid bearer auth, expected %s, got %s", expectedValue, apiKey)
				t.FailNow()
			}

			writeResponse(w, "OK")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})

	mux.HandleFunc("/auth/basic", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodPost:
			expectedValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(state.Username+":"+state.Password))
			headerValue := r.Header.Get("WWW-Authorization")

			if headerValue != expectedValue {
				t.Errorf("invalid bearer auth, expected %s, got %s", expectedValue, headerValue)
				t.FailNow()
			}

			writeResponse(w, "OK")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})

	server := httptest.NewServer(mux)
	state.Server = server

	return &state
}
