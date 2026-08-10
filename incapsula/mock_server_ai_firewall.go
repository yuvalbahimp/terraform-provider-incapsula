// Mock Imperva API Server — AI Firewall application endpoints
//
// Implements the stateful CRUD behaviour of the AI Firewall management service
// (/v3/api/applications) needed by the incapsula_ai_firewall_application
// acceptance tests. Requests and responses are wrapped in the backend
// ImpervaApiBody<T> envelope ({"data": …}), matching ApplicationController.

package incapsula

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// MockAiFirewallApplication represents an AI Firewall application in the mock server.
// Field shapes match ApplicationDetailsDto / ApplicationRequestDto.
type MockAiFirewallApplication struct {
	ApplicationId     string                       `json:"applicationId"`
	Name              string                       `json:"name"`
	AccountId         int64                        `json:"accountId"`
	Region            string                       `json:"region"`
	Status            string                       `json:"status"`
	StatusDescription string                       `json:"statusDescription"`
	ApplicationType   string                       `json:"applicationType"`
	Configuration     *AiFirewallApplicationConfig `json:"configuration,omitempty"`
}

// handleAiFirewallApplications routes AI Firewall application requests by method
// and whether an {applicationId} path segment is present.
func (m *MockImpervaServer) handleAiFirewallApplications(w http.ResponseWriter, r *http.Request, path string) {
	applicationID := strings.TrimPrefix(path, "v3/api/applications")
	applicationID = strings.TrimPrefix(applicationID, "/")

	switch r.Method {
	case http.MethodPost:
		m.handleAiFirewallApplicationCreate(w, r)
	case http.MethodGet:
		m.handleAiFirewallApplicationRead(w, r)
	case http.MethodPatch:
		m.handleAiFirewallApplicationUpdate(w, r, applicationID)
	case http.MethodDelete:
		m.handleAiFirewallApplicationDelete(w, applicationID)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		m.writeAiFirewallError(w, fmt.Sprintf("Method not allowed: %s", r.Method))
	}
}

// decodeAiFirewallRequest unwraps the {"data": {…}} envelope into an application request.
func (m *MockImpervaServer) decodeAiFirewallRequest(r *http.Request) (*AiFirewallApplicationRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var envelope AiFirewallImpervaApiBody
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}

	var req AiFirewallApplicationRequest
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// handleAiFirewallApplicationCreate handles POST /v3/api/applications.
func (m *MockImpervaServer) handleAiFirewallApplicationCreate(w http.ResponseWriter, r *http.Request) {
	req, err := m.decodeAiFirewallRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid request body: %s", err))
		return
	}

	// Capture the account the application belongs to from the caid query param
	// so Read (used on import) can echo it back via ApplicationDetailsDto.accountId.
	var accountID int64
	if caid := r.URL.Query().Get("caid"); caid != "" {
		if parsed, err := strconv.ParseInt(caid, 10, 64); err == nil {
			accountID = parsed
		}
	}

	m.mu.Lock()
	appID := fmt.Sprintf("00000000-0000-0000-0000-%012d", m.nextAiFirewallAppID)
	m.nextAiFirewallAppID++

	region := req.Region
	if region == "" {
		// Backend resolves an unset region from account-management, falling back to US.
		region = "US"
	}

	app := &MockAiFirewallApplication{
		ApplicationId:     appID,
		Name:              req.Name,
		AccountId:         accountID,
		Region:            region,
		Status:            "CONFIGURED",
		StatusDescription: "Application configured",
		ApplicationType:   req.ApplicationType,
		Configuration:     req.Configuration,
	}
	m.aiFirewallApplications[appID] = app
	m.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	m.writeAiFirewallObject(w, app)
}

// handleAiFirewallApplicationRead handles GET /v3/api/applications?applicationId=&caid=,
// returning ImpervaApiBody<List<ApplicationDetailsDto>>.
func (m *MockImpervaServer) handleAiFirewallApplicationRead(w http.ResponseWriter, r *http.Request) {
	applicationID := r.URL.Query().Get("applicationId")

	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*MockAiFirewallApplication, 0)
	if applicationID != "" {
		if app, ok := m.aiFirewallApplications[applicationID]; ok {
			list = append(list, app)
		}
	} else {
		for _, app := range m.aiFirewallApplications {
			list = append(list, app)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"data": list})
}

// handleAiFirewallApplicationUpdate handles PATCH /v3/api/applications/{applicationId}.
func (m *MockImpervaServer) handleAiFirewallApplicationUpdate(w http.ResponseWriter, r *http.Request, applicationID string) {
	req, err := m.decodeAiFirewallRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid request body: %s", err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	app, ok := m.aiFirewallApplications[applicationID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Application not found: %s", applicationID))
		return
	}

	// PATCH is partial: apply only fields present in the request.
	if req.Name != "" {
		app.Name = req.Name
	}
	if req.Region != "" {
		app.Region = req.Region
	}
	if req.Configuration != nil {
		app.Configuration = req.Configuration
	}

	w.WriteHeader(http.StatusOK)
	m.writeAiFirewallObject(w, app)
}

// handleAiFirewallApplicationDelete handles DELETE /v3/api/applications/{applicationId}.
func (m *MockImpervaServer) handleAiFirewallApplicationDelete(w http.ResponseWriter, applicationID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.aiFirewallApplications[applicationID]; !ok {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Application not found: %s", applicationID))
		return
	}

	delete(m.aiFirewallApplications, applicationID)
	w.WriteHeader(http.StatusNoContent)
}

// writeAiFirewallObject writes a single application wrapped in the {"data": {…}} envelope.
func (m *MockImpervaServer) writeAiFirewallObject(w http.ResponseWriter, app *MockAiFirewallApplication) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": app})
}

// writeAiFirewallError writes an ImpervaApiBody-style error body.
func (m *MockImpervaServer) writeAiFirewallError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []map[string]interface{}{
			{"detail": message},
		},
	})
}
