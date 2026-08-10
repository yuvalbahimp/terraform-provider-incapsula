package incapsula

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const aiFirewallApplicationEndpoint = "/v3/api/applications"

// AiFirewallImpervaApiBody wraps every AI Firewall write payload / response body
// (backend ImpervaApiBody<T> envelope, AIFW-1321). Shared by the policy and api-key resources.
type AiFirewallImpervaApiBody struct {
	Data json.RawMessage `json:"data"`
}

// AiFirewallApplicationRequest is the write payload for Create (POST) and Update (PATCH).
type AiFirewallApplicationRequest struct {
	Name            string                       `json:"name,omitempty"`
	ApplicationType string                       `json:"applicationType,omitempty"`
	Region          string                       `json:"region,omitempty"`
	Configuration   *AiFirewallApplicationConfig `json:"configuration,omitempty"`
}

// AiFirewallApplicationConfig matches ApplicationConfigurationDto.
type AiFirewallApplicationConfig struct {
	SiteId                   int64                        `json:"siteId,omitempty"`
	Path                     string                       `json:"path,omitempty"`
	ContentType              string                       `json:"contentType,omitempty"`
	PromptLocation           string                       `json:"promptLocation,omitempty"`
	BlockedResponseStructure string                       `json:"blocked_response_structure,omitempty"`
	IsStreaming              bool                         `json:"isStreaming"`
	Request                  *AiFirewallStreamingRequest  `json:"request,omitempty"`
	Response                 *AiFirewallStreamingResponse `json:"response,omitempty"`
}

// AiFirewallStreamingRequest matches StreamingRequestConfigDto.
type AiFirewallStreamingRequest struct {
	MessagePath string `json:"messagePath,omitempty"`
	ContentPath string `json:"contentPath,omitempty"`
	RolePath    string `json:"rolePath,omitempty"`
}

// AiFirewallStreamingResponse matches StreamingResponseConfigDto.
type AiFirewallStreamingResponse struct {
	RolePath          string `json:"rolePath,omitempty"`
	ContentPath       string `json:"contentPath,omitempty"`
	EndOfStreamMarker string `json:"endOfStreamMarker,omitempty"`
	FinishReasonPath  string `json:"finishReasonPath,omitempty"`
	FinishReasonValue string `json:"finishReasonValue,omitempty"`
}

// AiFirewallApplicationDetails matches ApplicationDetailsDto (flattened response shape).
type AiFirewallApplicationDetails struct {
	ApplicationId     string                       `json:"applicationId"`
	Name              string                       `json:"name"`
	AccountId         int64                        `json:"accountId"`
	Region            string                       `json:"region"`
	Status            string                       `json:"status"`
	StatusDescription string                       `json:"statusDescription"`
	ApplicationType   string                       `json:"applicationType"`
	Configuration     *AiFirewallApplicationConfig `json:"configuration,omitempty"`
}

type aiFirewallApplicationListResponse struct {
	Data []AiFirewallApplicationDetails `json:"data"`
}

type aiFirewallApplicationResponse struct {
	Data AiFirewallApplicationDetails `json:"data"`
}

func aiFirewallWrapData(payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}
	return json.Marshal(AiFirewallImpervaApiBody{Data: data})
}

// CreateAiFirewallApplication creates a new AI Firewall application.
// POST /v3/api/applications?caid={accountID}
func (c *Client) CreateAiFirewallApplication(accountID int, req *AiFirewallApplicationRequest) (*AiFirewallApplicationDetails, error) {
	reqURL := fmt.Sprintf("%s%s", c.config.BaseURLAiFirewall, aiFirewallApplicationEndpoint)
	params := GetRequestParamsWithCaid(accountID)

	body, err := aiFirewallWrapData(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Create AI Firewall application URL: %s, params: %s, body: %s", reqURL, params, string(body))

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodPost, reqURL, body, params, CreateAiFirewallApplication)
	if err != nil {
		return nil, fmt.Errorf("Error creating AI Firewall application: %s", err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading create AI Firewall application response: %s", err)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when creating application: %s", resp.StatusCode, string(responseBody))
	}

	var parsed aiFirewallApplicationResponse
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing create AI Firewall application JSON response: %s", err)
	}

	return &parsed.Data, nil
}

// GetAiFirewallApplication reads an AI Firewall application by ID.
// GET /v3/api/applications?caid={accountID}&applicationId={applicationID}
// Returns (nil, nil) if the application does not exist.
func (c *Client) GetAiFirewallApplication(accountID int, applicationID string) (*AiFirewallApplicationDetails, error) {
	reqURL := fmt.Sprintf("%s%s", c.config.BaseURLAiFirewall, aiFirewallApplicationEndpoint)
	params := GetRequestParamsWithCaid(accountID)
	params["applicationId"] = applicationID

	log.Printf("[DEBUG] Read AI Firewall application URL: %s, params: %s", reqURL, params)

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodGet, reqURL, nil, params, ReadAiFirewallApplication)
	if err != nil {
		return nil, fmt.Errorf("Error reading AI Firewall application with id %s: %s", applicationID, err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading AI Firewall application response body for id %s: %s", applicationID, err)
	}

	if resp.StatusCode == 404 {
		return nil, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when reading application %s: %s", resp.StatusCode, applicationID, string(responseBody))
	}

	var parsed aiFirewallApplicationListResponse
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing read AI Firewall application JSON response for id %s: %s", applicationID, err)
	}

	if len(parsed.Data) == 0 {
		return nil, nil
	}

	return &parsed.Data[0], nil
}

// UpdateAiFirewallApplication partially updates an AI Firewall application.
// PATCH /v3/api/applications/{applicationID}?caid={accountID}
func (c *Client) UpdateAiFirewallApplication(accountID int, applicationID string, req *AiFirewallApplicationRequest) (*AiFirewallApplicationDetails, error) {
	reqURL := fmt.Sprintf("%s%s/%s", c.config.BaseURLAiFirewall, aiFirewallApplicationEndpoint, applicationID)
	params := GetRequestParamsWithCaid(accountID)

	body, err := aiFirewallWrapData(req)
	if err != nil {
		return nil, err
	}

	log.Printf("[DEBUG] Update AI Firewall application URL: %s, params: %s, body: %s", reqURL, params, string(body))

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodPatch, reqURL, body, params, UpdateAiFirewallApplication)
	if err != nil {
		return nil, fmt.Errorf("Error updating AI Firewall application with id %s: %s", applicationID, err)
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading update AI Firewall application response body for id %s: %s", applicationID, err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error status code %d from AI Firewall service when updating application %s: %s", resp.StatusCode, applicationID, string(responseBody))
	}

	var parsed aiFirewallApplicationResponse
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return nil, fmt.Errorf("Error parsing update AI Firewall application JSON response for id %s: %s", applicationID, err)
	}

	return &parsed.Data, nil
}

// DeleteAiFirewallApplication deletes an AI Firewall application.
// DELETE /v3/api/applications/{applicationID}?caid={accountID}
func (c *Client) DeleteAiFirewallApplication(accountID int, applicationID string) error {
	reqURL := fmt.Sprintf("%s%s/%s", c.config.BaseURLAiFirewall, aiFirewallApplicationEndpoint, applicationID)
	params := GetRequestParamsWithCaid(accountID)

	log.Printf("[DEBUG] Delete AI Firewall application URL: %s, params: %s", reqURL, params)

	resp, err := c.DoJsonAndQueryParamsRequestWithHeaders(http.MethodDelete, reqURL, nil, params, DeleteAiFirewallApplication)
	if err != nil {
		return fmt.Errorf("Error deleting AI Firewall application with id %s: %s", applicationID, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		responseBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Error status code %d from AI Firewall service when deleting application %s: %s", resp.StatusCode, applicationID, string(responseBody))
	}

	return nil
}
