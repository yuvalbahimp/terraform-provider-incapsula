// Mock Imperva API Server — AI Firewall policy endpoints
//
// Implements the stateful CRUD behaviour of the AI Firewall management service
// (/v3/applications/{applicationId}/policies) needed by the
// incapsula_ai_firewall_policy acceptance tests. Requests and responses are wrapped
// in the backend ImpervaApiBody<T> envelope ({"data": …}), matching PolicyController.
//
// The backend enforces a single policy per application; the mock mirrors that.

package incapsula

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

// mockCaid extracts the caid query parameter as an int64 (0 if absent/invalid), so the
// mock can echo the owning account back on reads (used on import).
func mockCaid(r *http.Request) int64 {
	if caid := r.URL.Query().Get("caid"); caid != "" {
		if parsed, err := strconv.ParseInt(caid, 10, 64); err == nil {
			return parsed
		}
	}
	return 0
}

// MockAiFirewallPolicy represents an AI Firewall policy in the mock server.
// Field shapes match PolicyDto (guardians split into request/response phase buckets).
type MockAiFirewallPolicy struct {
	Id            string               `json:"id"`
	AccountId     int64                `json:"accountId"`
	ApplicationId string               `json:"applicationId"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Active        bool                 `json:"active"`
	Request       []AiFirewallGuardian `json:"request"`
	Response      []AiFirewallGuardian `json:"response"`
}

// handleAiFirewallPolicies routes AI Firewall policy requests. It parses the
// {applicationId} and optional {policyId} path segments robustly, tolerating the
// "/ai-application-security" prefix the client prepends to the mock base URL.
func (m *MockImpervaServer) handleAiFirewallPolicies(w http.ResponseWriter, r *http.Request, path string) {
	marker := "v3/applications/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid policy path: %s", path))
		return
	}
	// rest = {applicationId}/policies[/{policyId}]
	rest := path[idx+len(marker):]
	segments := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segments) < 2 || segments[1] != "policies" {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid policy path: %s", path))
		return
	}
	applicationID := segments[0]
	policyID := ""
	if len(segments) >= 3 {
		policyID = segments[2]
	}

	switch r.Method {
	case http.MethodPost:
		m.handleAiFirewallPolicyCreate(w, r, applicationID)
	case http.MethodGet:
		m.handleAiFirewallPolicyRead(w, policyID)
	case http.MethodPatch:
		m.handleAiFirewallPolicyUpdate(w, r, policyID)
	case http.MethodDelete:
		m.handleAiFirewallPolicyDelete(w, policyID)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		m.writeAiFirewallError(w, fmt.Sprintf("Method not allowed: %s", r.Method))
	}
}

// decodeAiFirewallPolicyRequest unwraps the {"data": {…}} envelope into a policy request.
func (m *MockImpervaServer) decodeAiFirewallPolicyRequest(r *http.Request) (*AiFirewallPolicyRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var envelope AiFirewallImpervaApiBody
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}

	var req AiFirewallPolicyRequest
	if err := json.Unmarshal(envelope.Data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// handleAiFirewallPolicyCreate handles POST /v3/applications/{applicationId}/policies.
func (m *MockImpervaServer) handleAiFirewallPolicyCreate(w http.ResponseWriter, r *http.Request, applicationID string) {
	req, err := m.decodeAiFirewallPolicyRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid request body: %s", err))
		return
	}

	accountID := mockCaid(r)

	m.mu.Lock()
	// Enforce a single policy per application, matching the backend.
	for _, p := range m.aiFirewallPolicies {
		if p.ApplicationId == applicationID {
			m.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			m.writeAiFirewallError(w, fmt.Sprintf("A policy already exists for application %s", applicationID))
			return
		}
	}

	policyID := fmt.Sprintf("aaaaaaaa-0000-0000-0000-%012d", m.nextAiFirewallPolicyID)
	m.nextAiFirewallPolicyID++

	policy := &MockAiFirewallPolicy{
		Id:            policyID,
		AccountId:     accountID,
		ApplicationId: applicationID,
		Name:          req.Name,
		Description:   req.Description,
		Active:        req.Active,
		Request:       normalizeGuardians(req.Request),
		Response:      normalizeGuardians(req.Response),
	}
	m.aiFirewallPolicies[policyID] = policy
	m.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
	m.writeAiFirewallPolicyObject(w, policy)
}

// handleAiFirewallPolicyRead handles GET /v3/applications/{applicationId}/policies/{policyId}.
// The backend looks the policy up by id regardless of the path's application segment.
func (m *MockImpervaServer) handleAiFirewallPolicyRead(w http.ResponseWriter, policyID string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, ok := m.aiFirewallPolicies[policyID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Policy not found: %s", policyID))
		return
	}

	w.WriteHeader(http.StatusOK)
	m.writeAiFirewallPolicyObject(w, policy)
}

// handleAiFirewallPolicyUpdate handles PATCH /v3/applications/{applicationId}/policies/{policyId}.
// Terraform always sends the full desired state, so every field is replaced.
func (m *MockImpervaServer) handleAiFirewallPolicyUpdate(w http.ResponseWriter, r *http.Request, policyID string) {
	req, err := m.decodeAiFirewallPolicyRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		m.writeAiFirewallError(w, fmt.Sprintf("Invalid request body: %s", err))
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	policy, ok := m.aiFirewallPolicies[policyID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Policy not found: %s", policyID))
		return
	}

	policy.Name = req.Name
	policy.Description = req.Description
	policy.Active = req.Active
	policy.Request = normalizeGuardians(req.Request)
	policy.Response = normalizeGuardians(req.Response)

	w.WriteHeader(http.StatusOK)
	m.writeAiFirewallPolicyObject(w, policy)
}

// handleAiFirewallPolicyDelete handles DELETE /v3/applications/{applicationId}/policies/{policyId}.
func (m *MockImpervaServer) handleAiFirewallPolicyDelete(w http.ResponseWriter, policyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.aiFirewallPolicies[policyID]; !ok {
		w.WriteHeader(http.StatusNotFound)
		m.writeAiFirewallError(w, fmt.Sprintf("Policy not found: %s", policyID))
		return
	}

	delete(m.aiFirewallPolicies, policyID)
	w.WriteHeader(http.StatusNoContent)
}

// writeAiFirewallPolicyObject writes a single policy wrapped in the {"data": {…}} envelope.
func (m *MockImpervaServer) writeAiFirewallPolicyObject(w http.ResponseWriter, policy *MockAiFirewallPolicy) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"data": policy})
}

// normalizeGuardians returns a non-nil slice so the {"data": …} envelope always carries
// request/response arrays (never JSON null), matching the backend's serialization.
func normalizeGuardians(guardians []AiFirewallGuardian) []AiFirewallGuardian {
	if guardians == nil {
		return []AiFirewallGuardian{}
	}
	return guardians
}
