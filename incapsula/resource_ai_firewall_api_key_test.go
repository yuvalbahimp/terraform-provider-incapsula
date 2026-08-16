package incapsula

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const aiFirewallApiKeyResourceName = "incapsula_ai_firewall_api_key.test"

// TestAccIncapsulaAiFirewallApiKeyBasic exercises the API key lifecycle against the mock
// server: create -> read -> import -> destroy. Because the plaintext api_key is only
// returned on create and is unrecoverable afterward, the test asserts it is non-empty
// after create and is (intentionally) ignored on import (empty after import).
func TestAccIncapsulaAiFirewallApiKeyBasic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallApiKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallApiKeyConfig("my-key"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApiKeyExists(aiFirewallApiKeyResourceName),
					resource.TestCheckResourceAttr(aiFirewallApiKeyResourceName, "name", "my-key"),
					resource.TestCheckResourceAttrSet(aiFirewallApiKeyResourceName, "api_key_id"),
					resource.TestCheckResourceAttrSet(aiFirewallApiKeyResourceName, "application_id"),
					resource.TestCheckResourceAttrSet(aiFirewallApiKeyResourceName, "masked_api_key"),
					// The plaintext key must be present after create.
					resource.TestCheckResourceAttrSet(aiFirewallApiKeyResourceName, "api_key"),
					resource.TestCheckResourceAttr(aiFirewallApiKeyResourceName, "active", "true"),
				),
			},
			{
				ResourceName:      aiFirewallApiKeyResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				// api_key (plaintext) is only returned on create and cannot be recovered on
				// read/import, so it is empty after import and must be excluded from verify.
				ImportStateVerifyIgnore: []string{"api_key"},
				ImportStateIdFunc:       aiFirewallApiKeyImportID(aiFirewallApiKeyResourceName),
			},
		},
	})
}

func testAccAiFirewallApiKeyConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "api_key_app" {
  account_id       = %d
  name             = "api-key-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_api_key" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.api_key_app.application_id
  name           = "%s"
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name)
}

// aiFirewallApiKeyImportID resolves the import key (numeric API key ID) for the named
// resource from Terraform state.
func aiFirewallApiKeyImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}
		return rs.Primary.ID, nil
	}
}

func testAccCheckAiFirewallApiKeyExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No API key ID is set")
		}

		apiKeyID, err := strconv.ParseInt(rs.Primary.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("Invalid API key ID %q: %s", rs.Primary.ID, err)
		}

		client := testAccProvider.Meta().(*Client)

		apiKey, err := client.GetAiFirewallApiKey(aiFirewallTestAccountID(), apiKeyID)
		if err != nil {
			return fmt.Errorf("Error getting AI Firewall API key: %s", err)
		}
		if apiKey == nil {
			return fmt.Errorf("AI Firewall API key %s not found", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckAiFirewallApiKeyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "incapsula_ai_firewall_api_key" {
			continue
		}
		if rs.Primary.ID == "" {
			continue
		}

		apiKeyID, err := strconv.ParseInt(rs.Primary.ID, 10, 64)
		if err != nil {
			continue
		}

		apiKey, err := client.GetAiFirewallApiKey(aiFirewallTestAccountID(), apiKeyID)
		if err == nil && apiKey != nil {
			return fmt.Errorf("AI Firewall API key still exists: %s", rs.Primary.ID)
		}
	}

	return nil
}
