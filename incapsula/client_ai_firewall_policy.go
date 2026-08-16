package incapsula

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// aiFirewallPolicyEndpoint is the application-scoped policy collection path (PolicyController,
// @RequestMapping("/v3/applications/{applicationId}/policies")). Format it with the
// application UUID to get the collection URL; append "/{policyId}" for item operations.
const aiFirewallPolicyEndpoint = "/ai-application-security/v3/applications/%s/policies"

// aiFirewallPolicyImportApplicationPlaceholder is used as the {applicationId} path segment
// when the real application id is unknown (policyId-only import). The backend
// getPolicyById(accountId, policyId) ignores the path segment and looks the policy up by id,
// so any syntactically valid UUID works; the response then carries the real applicationId.
const aiFirewallPolicyImportApplicationPlaceholder = "00000000-0000-0000-0000-000000000000"

// AiFirewallGuardian matches GuardianRequestDto (write) and GuardianDto (read) — they share
// the guardianType/guardianMode/guardianPhase/config/active JSON field names. Config carries
// the "type" discriminator required by the backend's polymorphic BaseGuardianConfigDto
// (@JsonTypeInfo(property="type")); the resource layer injects it on write and strips it on read.
type AiFirewallGuardian struct {
	GuardianType  string          `json:"guardianType"`
	GuardianMode  string          `json:"guardianMode"`
	GuardianPhase string          `json:"guardianPhase"`
	Active        bool            `json:"active"`
	Config        json.RawMessage `json:"config,omitempty"`
}

// AiFirewallPolicyRequest is the write payload for Create (POST) and Update (PATCH). It matches
// CreatePolicyRequestDto and PatchPolicyRequestDto: because Terraform always sends the full
// desired state, a single PATCH covers field-only, guardian-only, and combined changes.
type AiFirewallPolicyRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Active      bool                 `json:"active"`
	Request     []AiFirewallGuardian `json:"request"`
	Response    []AiFirewallGuardian `json:"response"`
}

// AiFirewallPolicyResponse matches PolicyDto (the subset the resource consumes).
type AiFirewallPolicyResponse struct {
	Id            string               `json:"id"`
	AccountId     int64                `json:"accountId"`
	ApplicationId string               `json:"applicationId"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Active        bool                 `json:"active"`
	Request       []AiFirewallGuardian `json:"request"`
	Response      []AiFirewallGuardian `json:"response"`
}

type aiFirewallPolicyResponseBody struct {
	Data AiFirewallPolicyResponse `json:"data"`
}

// aiFirewallPolicyCollectionURL builds the application-scoped policy collection URL.
func (c *Client) aiFirewallPolicyCollectionURL(applicationID string) string {
	return c.config.BaseURLAPI + fmt.Sprintf(aiFirewallPolicyEndpoint, applicationID)
}

// CreateAiFirewallPolicy creates the (single) policy for an application.
// POST /ai-application-security/v3/applications/{applicationID}/policies?caid={accountID}
func (c *Client) CreateAiFirewallPolicy(accountID int, applicationID string, req *AiFirewallPolicyRequest) (*AiFirewallPolicyResponse, error) {
	reqURL := c.aiFirewallPolicyCollectionURL(applicationID)
	params := GetRequestParamsWithCaid(accountID)

	body, err := aiFirewallWrapData(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Create AI Firewall policy URL: %s, params: %s, body: %s", reqURL, params, string(body))

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodPost, reqURL, body, params, CreateAiFirewallPolicy)
	if err != nil {
		return nil, fmt.Errorf("Error creating AI Firewall policy: %s", err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading create AI Firewall policy response: %s", err)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when creating policy for application %s: %s", resp.StatusCode, applicationID, string(responseBody))
	}

	var parsed aiFirewallPolicyResponseBody
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing create AI Firewall policy JSON response: %s", err)
	}

	return &parsed.Data, nil
}

// GetAiFirewallPolicy reads a policy by id.
// GET /ai-application-security/v3/applications/{applicationID}/policies/{policyID}?caid={accountID}
// Returns (nil, nil) if the policy does not exist.
func (c *Client) GetAiFirewallPolicy(accountID int, applicationID string, policyID string) (*AiFirewallPolicyResponse, error) {
	reqURL := fmt.Sprintf("%s/%s", c.aiFirewallPolicyCollectionURL(applicationID), policyID)
	params := GetRequestParamsWithCaid(accountID)

	log.Printf("[DEBUG] Read AI Firewall policy URL: %s, params: %s", reqURL, params)

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodGet, reqURL, nil, params, ReadAiFirewallPolicy)
	if err != nil {
		return nil, fmt.Errorf("Error reading AI Firewall policy with id %s: %s", policyID, err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading AI Firewall policy response body for id %s: %s", policyID, err)
	}

	if resp.StatusCode == 404 {
		return nil, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when reading policy %s: %s", resp.StatusCode, policyID, string(responseBody))
	}

	var parsed aiFirewallPolicyResponseBody
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing read AI Firewall policy JSON response for id %s: %s", policyID, err)
	}

	return &parsed.Data, nil
}

// UpdateAiFirewallPolicy updates a policy with the full desired state via PATCH.
// PATCH /ai-application-security/v3/applications/{applicationID}/policies/{policyID}?caid={accountID}
func (c *Client) UpdateAiFirewallPolicy(accountID int, applicationID string, policyID string, req *AiFirewallPolicyRequest) (*AiFirewallPolicyResponse, error) {
	reqURL := fmt.Sprintf("%s/%s", c.aiFirewallPolicyCollectionURL(applicationID), policyID)
	params := GetRequestParamsWithCaid(accountID)

	body, err := aiFirewallWrapData(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Update AI Firewall policy URL: %s, params: %s, body: %s", reqURL, params, string(body))

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodPatch, reqURL, body, params, UpdateAiFirewallPolicy)
	if err != nil {
		return nil, fmt.Errorf("Error updating AI Firewall policy with id %s: %s", policyID, err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading update AI Firewall policy response body for id %s: %s", policyID, err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when updating policy %s: %s", resp.StatusCode, policyID, string(responseBody))
	}

	var parsed aiFirewallPolicyResponseBody
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing update AI Firewall policy JSON response for id %s: %s", policyID, err)
	}

	return &parsed.Data, nil
}

// DeleteAiFirewallPolicy deletes a policy by id.
// DELETE /ai-application-security/v3/applications/{applicationID}/policies/{policyID}?caid={accountID}
func (c *Client) DeleteAiFirewallPolicy(accountID int, applicationID string, policyID string) error {
	reqURL := fmt.Sprintf("%s/%s", c.aiFirewallPolicyCollectionURL(applicationID), policyID)
	params := GetRequestParamsWithCaid(accountID)

	log.Printf("[DEBUG] Delete AI Firewall policy URL: %s, params: %s", reqURL, params)

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodDelete, reqURL, nil, params, DeleteAiFirewallPolicy)
	if err != nil {
		return fmt.Errorf("Error deleting AI Firewall policy with id %s: %s", policyID, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		responseBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Error status code %d from AI Firewall service when deleting policy %s: %s", resp.StatusCode, policyID, string(responseBody))
	}

	return nil
}
