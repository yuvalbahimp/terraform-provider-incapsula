package incapsula

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// Guardian phase values.
const (
	aiFirewallGuardianPhasePrompt   = "PROMPT"
	aiFirewallGuardianPhaseResponse = "RESPONSE"
)

// aiFirewallGuardianValidPhases maps each guardian type to the phases it may run in,
// mirroring the backend's per-guardian phase validation. Enforced at plan time by
// resourceAiFirewallPolicyCustomizeDiff so misconfigurations fail before any API call.
var aiFirewallGuardianValidPhases = map[string][]string{
	"PROMPT_INJECTION":         {aiFirewallGuardianPhasePrompt},
	"MODERATION":               {aiFirewallGuardianPhaseResponse},
	"SYSTEM_PROMPT_LEAK":       {aiFirewallGuardianPhaseResponse},
	"PII_STATIC":               {aiFirewallGuardianPhasePrompt, aiFirewallGuardianPhaseResponse},
	"RATE_LIMIT":               {aiFirewallGuardianPhasePrompt, aiFirewallGuardianPhaseResponse},
	"ZERO_SHOT_CLASSIFICATION": {aiFirewallGuardianPhasePrompt, aiFirewallGuardianPhaseResponse},
}

func aiFirewallGuardianTypes() []string {
	types := make([]string, 0, len(aiFirewallGuardianValidPhases))
	for t := range aiFirewallGuardianValidPhases {
		types = append(types, t)
	}
	return types
}

func resourceAiFirewallPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAiFirewallPolicyCreate,
		ReadContext:   resourceAiFirewallPolicyRead,
		UpdateContext: resourceAiFirewallPolicyUpdate,
		DeleteContext: resourceAiFirewallPolicyDelete,
		CustomizeDiff: resourceAiFirewallPolicyCustomizeDiff,
		Importer: &schema.ResourceImporter{
			StateContext: resourceAiFirewallPolicyImport,
		},

		Description: "Manages an AI Firewall policy for an application. A policy holds an ordered " +
			"set of guardians, each attached to the PROMPT (request) or RESPONSE phase.",

		Schema: map[string]*schema.Schema{
			"account_id": {
				Type:        schema.TypeInt,
				Description: "The Imperva account ID that owns the application. Defaults to the account of the API credentials when omitted.",
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
			},
			"application_id": {
				Type:         schema.TypeString,
				Description:  "The UUID of the AI Firewall application this policy belongs to.",
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsUUID,
			},
			"name": {
				Type:         schema.TypeString,
				Description:  "The policy name.",
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 100),
			},
			"description": {
				Type:         schema.TypeString,
				Description:  "An optional description of the policy.",
				Optional:     true,
				ValidateFunc: validation.StringLenBetween(0, 500),
			},
			"active": {
				Type:        schema.TypeBool,
				Description: "Whether the policy is active. Defaults to true.",
				Optional:    true,
				Default:     true,
			},
			"guardian": {
				Type:        schema.TypeSet,
				Description: "The set of guardians enforced by this policy. At least one is required.",
				Required:    true,
				MinItems:    1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"type": {
							Type:         schema.TypeString,
							Description:  "The guardian type.",
							Required:     true,
							ValidateFunc: validation.StringInSlice(aiFirewallGuardianTypes(), false),
						},
						"phase": {
							Type:         schema.TypeString,
							Description:  "The phase the guardian runs in: PROMPT (request) or RESPONSE.",
							Required:     true,
							ValidateFunc: validation.StringInSlice([]string{aiFirewallGuardianPhasePrompt, aiFirewallGuardianPhaseResponse}, false),
						},
						"mode": {
							Type:         schema.TypeString,
							Description:  "The enforcement mode: BLOCK, ALERT, or MASK.",
							Required:     true,
							ValidateFunc: validation.StringInSlice([]string{"BLOCK", "ALERT", "MASK"}, false),
						},
						"active": {
							Type:        schema.TypeBool,
							Description: "Whether this guardian is active. Defaults to true.",
							Optional:    true,
							Default:     true,
						},
						"config": {
							Type:         schema.TypeString,
							Description:  "Guardian-specific configuration as a JSON object. Defaults to an empty object.",
							Optional:     true,
							Default:      "{}",
							ValidateFunc: validation.StringIsJSON,
							// guardian is a TypeSet, whose element hash is computed from the raw
							// attribute values BEFORE DiffSuppressFunc runs — so a suppressor alone
							// cannot prevent spurious add/remove diffs when the backend returns
							// semantically-equal but reordered JSON. The set's Set hash function (see
							// below) normalizes this config before hashing so both sides hash
							// identically; DiffSuppressFunc then suppresses the intra-element string
							// diff for the (now hash-matched) element.
							DiffSuppressFunc: suppressEquivalentJSONStringDiffs,
						},
					},
				},
				// A guardian's config is JSON whose key order is not significant, but a TypeSet
				// hashes the raw attribute values, so a config written with keys in one order
				// would hash differently than the same config read back sorted (see
				// flattenAiFirewallGuardian) — producing a perpetual remove/add diff. Hash the
				// normalized config instead so semantically-equal guardians land in the same
				// set element.
				Set: aiFirewallGuardianHash,
			},
		},
	}
}

// aiFirewallGuardianHash computes the set hash for a guardian element from its identifying
// fields plus its normalized (canonical-JSON) config, so that guardians differing only in
// config key order hash identically.
func aiFirewallGuardianHash(v interface{}) int {
	m := v.(map[string]interface{})
	var b strings.Builder
	b.WriteString(m["type"].(string))
	b.WriteString("|")
	b.WriteString(m["phase"].(string))
	b.WriteString("|")
	b.WriteString(m["mode"].(string))
	b.WriteString("|")
	b.WriteString(strconv.FormatBool(m["active"].(bool)))
	b.WriteString("|")
	b.WriteString(normalizeAiFirewallGuardianConfig(m["config"]))
	return schema.HashString(b.String())
}

// resourceAiFirewallPolicyCustomizeDiff validates each guardian's type/phase combination
// against aiFirewallGuardianValidPhases at plan time.
func resourceAiFirewallPolicyCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
	guardians, ok := d.Get("guardian").(*schema.Set)
	if !ok {
		return nil
	}
	for _, raw := range guardians.List() {
		g := raw.(map[string]interface{})
		guardianType := g["type"].(string)
		phase := g["phase"].(string)
		validPhases, known := aiFirewallGuardianValidPhases[guardianType]
		if !known {
			// Unknown type is caught by the schema ValidateFunc; skip here.
			continue
		}
		if !stringInSlice(validPhases, phase) {
			return fmt.Errorf("guardian type %q is not valid in phase %q; allowed phases: %s",
				guardianType, phase, strings.Join(validPhases, ", "))
		}
	}
	return nil
}

func stringInSlice(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func resourceAiFirewallPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)

	req, err := buildAiFirewallPolicyRequest(d)
	if err != nil {
		return diag.FromErr(err)
	}

	policy, err := client.CreateAiFirewallPolicy(accountID, applicationID, req)
	if err != nil {
		return diag.Errorf("Failed to create AI Firewall policy for application %s: %s", applicationID, err)
	}

	d.SetId(policy.Id)

	return resourceAiFirewallPolicyRead(ctx, d, m)
}

func resourceAiFirewallPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)
	if applicationID == "" {
		// On policyId-only import the application id is unknown; the backend looks the
		// policy up by id regardless of the path segment.
		applicationID = aiFirewallPolicyImportApplicationPlaceholder
	}
	policyID := d.Id()

	policy, err := client.GetAiFirewallPolicy(accountID, applicationID, policyID)
	if err != nil {
		return diag.Errorf("Failed to read AI Firewall policy %s: %s", policyID, err)
	}
	if policy == nil {
		d.SetId("")
		return nil
	}

	d.Set("account_id", int(policy.AccountId))
	d.Set("application_id", policy.ApplicationId)
	d.Set("name", policy.Name)
	d.Set("description", policy.Description)
	d.Set("active", policy.Active)

	guardians, err := flattenAiFirewallGuardians(policy)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("guardian", guardians); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceAiFirewallPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)
	policyID := d.Id()

	req, err := buildAiFirewallPolicyRequest(d)
	if err != nil {
		return diag.FromErr(err)
	}

	if _, err := client.UpdateAiFirewallPolicy(accountID, applicationID, policyID, req); err != nil {
		return diag.Errorf("Failed to update AI Firewall policy %s: %s", policyID, err)
	}

	return resourceAiFirewallPolicyRead(ctx, d, m)
}

func resourceAiFirewallPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)
	policyID := d.Id()

	if err := client.DeleteAiFirewallPolicy(accountID, applicationID, policyID); err != nil {
		return diag.Errorf("Failed to delete AI Firewall policy %s: %s", policyID, err)
	}

	d.SetId("")
	return nil
}

// buildAiFirewallPolicyRequest assembles the full desired-state write payload from the
// resource data, splitting guardians into their request/response phase buckets.
func buildAiFirewallPolicyRequest(d *schema.ResourceData) (*AiFirewallPolicyRequest, error) {
	requestGuardians, responseGuardians, err := expandAiFirewallGuardians(d.Get("guardian").(*schema.Set))
	if err != nil {
		return nil, err
	}

	return &AiFirewallPolicyRequest{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Active:      d.Get("active").(bool),
		Request:     requestGuardians,
		Response:    responseGuardians,
	}, nil
}

// expandAiFirewallGuardians converts the guardian set into the backend's phase-split
// request/response slices, injecting the "type" discriminator into each guardian's config.
func expandAiFirewallGuardians(set *schema.Set) (request []AiFirewallGuardian, response []AiFirewallGuardian, err error) {
	request = []AiFirewallGuardian{}
	response = []AiFirewallGuardian{}

	for _, raw := range set.List() {
		g := raw.(map[string]interface{})
		guardian, err := buildAiFirewallGuardian(g)
		if err != nil {
			return nil, nil, err
		}
		if guardian.GuardianPhase == aiFirewallGuardianPhasePrompt {
			request = append(request, guardian)
		} else {
			response = append(response, guardian)
		}
	}

	return request, response, nil
}

// buildAiFirewallGuardian maps one guardian set element to an AiFirewallGuardian, injecting
// the guardian type into the config JSON as the "type" discriminator required by the
// backend's polymorphic BaseGuardianConfigDto.
func buildAiFirewallGuardian(g map[string]interface{}) (AiFirewallGuardian, error) {
	guardianType := g["type"].(string)

	configStr, _ := g["config"].(string)
	if strings.TrimSpace(configStr) == "" {
		configStr = "{}"
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &configMap); err != nil {
		return AiFirewallGuardian{}, fmt.Errorf("guardian config for type %s is not valid JSON: %s", guardianType, err)
	}
	if configMap == nil {
		configMap = map[string]interface{}{}
	}
	if _, present := configMap["type"]; !present {
		configMap["type"] = guardianType
	}

	configRaw, err := json.Marshal(configMap)
	if err != nil {
		return AiFirewallGuardian{}, fmt.Errorf("failed to encode guardian config for type %s: %s", guardianType, err)
	}

	return AiFirewallGuardian{
		GuardianType:  guardianType,
		GuardianMode:  g["mode"].(string),
		GuardianPhase: g["phase"].(string),
		Active:        g["active"].(bool),
		Config:        configRaw,
	}, nil
}

// flattenAiFirewallGuardians merges the phase-split response slices back into a single set,
// stripping the injected "type" discriminator so it round-trips against the user's config.
func flattenAiFirewallGuardians(policy *AiFirewallPolicyResponse) ([]interface{}, error) {
	all := make([]interface{}, 0, len(policy.Request)+len(policy.Response))

	for _, g := range policy.Request {
		f, err := flattenAiFirewallGuardian(g, aiFirewallGuardianPhasePrompt)
		if err != nil {
			return nil, err
		}
		all = append(all, f)
	}
	for _, g := range policy.Response {
		f, err := flattenAiFirewallGuardian(g, aiFirewallGuardianPhaseResponse)
		if err != nil {
			return nil, err
		}
		all = append(all, f)
	}

	return all, nil
}

// normalizeAiFirewallGuardianConfig canonicalizes a guardian config JSON string (sorted keys,
// no insignificant whitespace) so it matches flattenAiFirewallGuardian's json.Marshal output.
// Because config lives inside a TypeSet, the stored value feeds the set-element hash; storing a
// canonical form on both the config and refresh sides keeps the hashes stable. Invalid JSON is
// returned unchanged so ValidateFunc surfaces the error instead of this masking it.
func normalizeAiFirewallGuardianConfig(v interface{}) string {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "{}"
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(s), &parsed); err != nil {
		return s
	}
	canonical, err := json.Marshal(parsed)
	if err != nil {
		return s
	}
	return string(canonical)
}

func flattenAiFirewallGuardian(g AiFirewallGuardian, phaseFallback string) (map[string]interface{}, error) {
	phase := g.GuardianPhase
	if phase == "" {
		phase = phaseFallback
	}

	configStr := "{}"
	if len(g.Config) > 0 {
		var configMap map[string]interface{}
		if err := json.Unmarshal(g.Config, &configMap); err != nil {
			return nil, fmt.Errorf("guardian config from backend for type %s is not valid JSON: %s", g.GuardianType, err)
		}
		// The "type" discriminator is injected on write; strip it so state matches config.
		delete(configMap, "type")
		configRaw, err := json.Marshal(configMap)
		if err != nil {
			return nil, fmt.Errorf("failed to encode guardian config for type %s: %s", g.GuardianType, err)
		}
		configStr = string(configRaw)
	}

	return map[string]interface{}{
		"type":   g.GuardianType,
		"mode":   g.GuardianMode,
		"phase":  phase,
		"active": g.Active,
		"config": configStr,
	}, nil
}

func resourceAiFirewallPolicyImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	raw := strings.TrimSpace(d.Id())
	if raw == "" {
		return nil, fmt.Errorf("expected import ID to be '<policy_id>' or '<account_id>/<policy_id>'")
	}

	var accountID string
	resourceID := raw

	if strings.Contains(raw, "/") {
		parts := strings.SplitN(raw, "/", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid import ID %q: want '<policy_id>' or '<account_id>/<policy_id>'", raw)
		}
		accountID = strings.TrimSpace(parts[0])
		resourceID = strings.TrimSpace(parts[1])
	}

	// Set the canonical Terraform ID to just the resource ID.
	d.SetId(resourceID)

	// Only set account_id if it was provided.
	if accountID != "" {
		caid, err := strconv.Atoi(accountID)
		if err != nil {
			return nil, fmt.Errorf("invalid account_id %q: must be numeric", accountID)
		}
		if err := d.Set("account_id", caid); err != nil {
			return nil, fmt.Errorf("setting account_id: %w", err)
		}
	}

	return []*schema.ResourceData{d}, nil
}
