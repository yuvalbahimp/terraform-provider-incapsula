package incapsula

import (
	"context"
	"log"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAiFirewallApiKey() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAiFirewallApiKeyCreate,
		ReadContext:   resourceAiFirewallApiKeyRead,
		DeleteContext: resourceAiFirewallApiKeyDelete,
		// No UpdateContext: only name is settable and the backend has no update endpoint,
		// so every input is ForceNew.
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Description: "Manages an AI Firewall API key for an application. The plaintext key is " +
			"returned only once, on create, in the sensitive api_key attribute and cannot be " +
			"recovered afterward (it is empty after import). All inputs are immutable.",

		Schema: map[string]*schema.Schema{
			"account_id": {
				Type:        schema.TypeInt,
				Description: "The Imperva account ID that owns the application.",
				Required:    true,
				ForceNew:    true,
			},
			"application_id": {
				Type:         schema.TypeString,
				Description:  "The UUID of the AI Firewall application this API key belongs to.",
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsUUID,
			},
			"name": {
				Type:        schema.TypeString,
				Description: "The API key name (1-50 chars, alphanumeric, underscore or hyphen).",
				Required:    true,
				ForceNew:    true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 50),
					validation.StringMatch(regexp.MustCompile(`^[a-zA-Z0-9_-]+$`), "must be alphanumeric, underscore or hyphen"),
				),
			},
			"api_key": {
				Type:        schema.TypeString,
				Description: "The plaintext API key. Returned only once on creation and unrecoverable afterward; empty after import.",
				Computed:    true,
				Sensitive:   true,
			},
			"api_key_id": {
				Type:        schema.TypeInt,
				Description: "The numeric ID of the API key (same as the resource ID).",
				Computed:    true,
			},
			"masked_api_key": {
				Type:        schema.TypeString,
				Description: "The masked representation of the API key.",
				Computed:    true,
			},
			"active": {
				Type:        schema.TypeBool,
				Description: "Whether the API key is active.",
				Computed:    true,
			},
			"created_at": {
				Type:        schema.TypeInt,
				Description: "Creation time of the API key (epoch milliseconds).",
				Computed:    true,
			},
			"last_used_at": {
				Type:        schema.TypeInt,
				Description: "Last-used time of the API key (epoch milliseconds); 0 if never used.",
				Computed:    true,
			},
		},
	}
}

func resourceAiFirewallApiKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)

	req := &AiFirewallApiKeyRequest{
		Name: d.Get("name").(string),
	}

	created, err := client.CreateAiFirewallApiKey(accountID, applicationID, req)
	if err != nil {
		return diag.Errorf("Failed to create AI Firewall API key for application %s: %s", applicationID, err)
	}

	// The plaintext key is available only in this response; persist it now — Read never touches it.
	d.Set("api_key", created.FullKey)
	d.Set("api_key_id", int(created.ApiKey.Id))
	d.SetId(strconv.FormatInt(created.ApiKey.Id, 10))
	log.Printf("[INFO] Created AI Firewall API key with ID: %d", created.ApiKey.Id)

	return resourceAiFirewallApiKeyRead(ctx, d, m)
}

func resourceAiFirewallApiKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)

	apiKeyID, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return diag.Errorf("Invalid AI Firewall API key ID %q: %s", d.Id(), err)
	}

	apiKey, err := client.GetAiFirewallApiKey(accountID, apiKeyID)
	if err != nil {
		return diag.Errorf("Failed to read AI Firewall API key %d: %s", apiKeyID, err)
	}
	if apiKey == nil {
		log.Printf("[INFO] AI Firewall API key %d not found, removing from state", apiKeyID)
		d.SetId("")
		return nil
	}

	// Note: api_key (plaintext) is intentionally NOT set here — it is unavailable on read
	// and must retain its create-time value (empty after import).
	if apiKey.AccountId != 0 {
		d.Set("account_id", int(apiKey.AccountId))
	}
	d.Set("application_id", apiKey.ApplicationId)
	d.Set("name", apiKey.Name)
	d.Set("api_key_id", int(apiKey.Id))
	d.Set("masked_api_key", apiKey.MaskedApiKey)
	d.Set("active", apiKey.Active)
	d.Set("created_at", int(apiKey.CreatedAt))
	d.Set("last_used_at", int(apiKey.LastUsedAt))

	return nil
}

func resourceAiFirewallApiKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	accountID := d.Get("account_id").(int)
	applicationID := d.Get("application_id").(string)

	apiKeyID, err := strconv.ParseInt(d.Id(), 10, 64)
	if err != nil {
		return diag.Errorf("Invalid AI Firewall API key ID %q: %s", d.Id(), err)
	}

	if err := client.DeleteAiFirewallApiKey(accountID, applicationID, apiKeyID); err != nil {
		return diag.Errorf("Failed to delete AI Firewall API key %d: %s", apiKeyID, err)
	}

	d.SetId("")
	return nil
}
