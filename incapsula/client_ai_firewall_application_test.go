package incapsula

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAiFirewallApplicationBadConnection(t *testing.T) {
	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: "badness.incapsula.com"}
	client := &Client{config: config, httpClient: &http.Client{Timeout: 1}}

	_, err := client.CreateAiFirewallApplication(55, &AiFirewallApplicationRequest{Name: "app"})
	if err == nil {
		t.Errorf("Should have received an error")
	}

	_, err = client.GetAiFirewallApplication(55, "app-id")
	if err == nil {
		t.Errorf("Should have received an error")
	}

	_, err = client.UpdateAiFirewallApplication(55, "app-id", &AiFirewallApplicationRequest{})
	if err == nil {
		t.Errorf("Should have received an error")
	}

	err = client.DeleteAiFirewallApplication(55, "app-id")
	if err == nil {
		t.Errorf("Should have received an error")
	}
}

func TestAiFirewallApplicationCreate(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	accountID := 55
	expectedEndpoint := fmt.Sprintf("%s?caid=%d", aiFirewallApplicationEndpoint, accountID)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != expectedEndpoint {
			t.Errorf("Should have hit %s endpoint. Got: %s", expectedEndpoint, req.URL.String())
		}
		if req.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", req.Method)
		}

		var envelope AiFirewallImpervaApiBody
		if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
			t.Fatalf("Failed to decode request body envelope: %s", err)
		}
		var payload AiFirewallApplicationRequest
		if err := json.Unmarshal(envelope.Data, &payload); err != nil {
			t.Fatalf("Failed to decode envelope data: %s", err)
		}
		if payload.Name != "my-app" {
			t.Errorf("Expected name my-app, got %s", payload.Name)
		}

		rw.WriteHeader(201)
		rw.Write([]byte(`{"data":{"applicationId":"11111111-1111-1111-1111-111111111111","name":"my-app","applicationType":"API","region":"US","status":"CONFIGURED"}}`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	resp, err := client.CreateAiFirewallApplication(accountID, &AiFirewallApplicationRequest{Name: "my-app", ApplicationType: "API"})
	if err != nil {
		t.Fatalf("Should not have received an error, got: %s", err)
	}
	if resp.ApplicationId != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("Unexpected application id: %s", resp.ApplicationId)
	}
}

func TestAiFirewallApplicationRead(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	accountID := 55
	applicationID := "11111111-1111-1111-1111-111111111111"
	expectedEndpoint := fmt.Sprintf("%s?applicationId=%s&caid=%d", aiFirewallApplicationEndpoint, applicationID, accountID)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != expectedEndpoint {
			t.Errorf("Should have hit %s endpoint. Got: %s", expectedEndpoint, req.URL.String())
		}
		if req.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", req.Method)
		}
		rw.WriteHeader(200)
		rw.Write([]byte(`{"data":[{"applicationId":"11111111-1111-1111-1111-111111111111","name":"my-app","applicationType":"API","region":"US","status":"CONFIGURED"}]}`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	resp, err := client.GetAiFirewallApplication(accountID, applicationID)
	if err != nil {
		t.Fatalf("Should not have received an error, got: %s", err)
	}
	if resp == nil || resp.Name != "my-app" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}

func TestAiFirewallApplicationReadEmptyList(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	resp, err := client.GetAiFirewallApplication(55, "does-not-exist")
	if err != nil {
		t.Fatalf("Should not have received an error, got: %s", err)
	}
	if resp != nil {
		t.Errorf("Expected nil response for empty list, got: %+v", resp)
	}
}

func TestAiFirewallApplicationReadNotFound(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(404)
		rw.Write([]byte(`{"errors":[{"status":"404"}]}`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	resp, err := client.GetAiFirewallApplication(55, "does-not-exist")
	if err != nil {
		t.Fatalf("Should not have received an error, got: %s", err)
	}
	if resp != nil {
		t.Errorf("Expected nil response for 404, got: %+v", resp)
	}
}

func TestAiFirewallApplicationUpdate(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	accountID := 55
	applicationID := "11111111-1111-1111-1111-111111111111"
	expectedEndpoint := fmt.Sprintf("%s/%s?caid=%d", aiFirewallApplicationEndpoint, applicationID, accountID)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != expectedEndpoint {
			t.Errorf("Should have hit %s endpoint. Got: %s", expectedEndpoint, req.URL.String())
		}
		if req.Method != http.MethodPatch {
			t.Errorf("Expected PATCH, got %s", req.Method)
		}

		var envelope AiFirewallImpervaApiBody
		if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
			t.Fatalf("Failed to decode request body envelope: %s", err)
		}

		rw.WriteHeader(200)
		rw.Write([]byte(`{"data":{"applicationId":"11111111-1111-1111-1111-111111111111","name":"renamed-app","applicationType":"API","region":"EU","status":"CONFIGURED"}}`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	resp, err := client.UpdateAiFirewallApplication(accountID, applicationID, &AiFirewallApplicationRequest{Name: "renamed-app", Region: "EU"})
	if err != nil {
		t.Fatalf("Should not have received an error, got: %s", err)
	}
	if resp.Name != "renamed-app" || resp.Region != "EU" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}

func TestAiFirewallApplicationDelete(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	accountID := 55
	applicationID := "11111111-1111-1111-1111-111111111111"
	expectedEndpoint := fmt.Sprintf("%s/%s?caid=%d", aiFirewallApplicationEndpoint, applicationID, accountID)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != expectedEndpoint {
			t.Errorf("Should have hit %s endpoint. Got: %s", expectedEndpoint, req.URL.String())
		}
		if req.Method != http.MethodDelete {
			t.Errorf("Expected DELETE, got %s", req.Method)
		}
		rw.WriteHeader(204)
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	err := client.DeleteAiFirewallApplication(accountID, applicationID)
	if err != nil {
		t.Errorf("Should not have received an error, got: %s", err)
	}
}

func TestAiFirewallApplicationErrorResponse(t *testing.T) {
	restore := withShortRetries()
	defer restore()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(500)
		rw.Write([]byte(`Server error`))
	}))
	defer server.Close()

	config := &Config{APIID: "foo", APIKey: "bar", BaseURLAPI: server.URL}
	client := &Client{config: config, httpClient: &http.Client{}}

	_, err := client.CreateAiFirewallApplication(55, &AiFirewallApplicationRequest{Name: "app"})
	if err == nil {
		t.Errorf("Should have received an error")
	}

	_, err = client.GetAiFirewallApplication(55, "app-id")
	if err == nil {
		t.Errorf("Should have received an error")
	}

	_, err = client.UpdateAiFirewallApplication(55, "app-id", &AiFirewallApplicationRequest{})
	if err == nil {
		t.Errorf("Should have received an error")
	}

	err = client.DeleteAiFirewallApplication(55, "app-id")
	if err == nil {
		t.Errorf("Should have received an error")
	}
}
