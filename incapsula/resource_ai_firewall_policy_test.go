package incapsula

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const aiFirewallPolicyResourceName = "incapsula_ai_firewall_policy.test"

// TestAccIncapsulaAiFirewallPolicyBasic exercises the full policy lifecycle against the
// mock server: create -> read -> update (rename + toggle active + mutate guardians via
// PATCH) -> import (ImportStateVerify) -> destroy.
func TestAccIncapsulaAiFirewallPolicyBasic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallPolicyConfig("my-policy", true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "name", "my-policy"),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "active", "true"),
					resource.TestCheckResourceAttrSet(aiFirewallPolicyResourceName, "policy_id"),
					resource.TestCheckResourceAttrSet(aiFirewallPolicyResourceName, "application_id"),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "2"),
				),
			},
			{
				Config: testAccAiFirewallPolicyConfig("renamed-policy", false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "name", "renamed-policy"),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "active", "false"),
				),
			},
			{
				ResourceName:      aiFirewallPolicyResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: aiFirewallPolicyImportID(aiFirewallPolicyResourceName),
			},
		},
	})
}

// TestAccIncapsulaAiFirewallPolicyInvalidPhase asserts the plan-time type/phase validation
// in resourceAiFirewallPolicyCustomizeDiff: PROMPT_INJECTION is only valid in the PROMPT
// phase, so declaring it in RESPONSE must fail before any backend call.
func TestAccIncapsulaAiFirewallPolicyInvalidPhase(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config:      testAccAiFirewallPolicyInvalidPhaseConfig("bad-policy"),
				ExpectError: regexp.MustCompile(`guardian type "PROMPT_INJECTION" is not valid in phase "RESPONSE"`),
			},
		},
	})
}

func testAccAiFirewallPolicyConfig(name string, active bool) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.application_id
  name           = "%s"
  active         = %t

  guardian {
    type  = "PROMPT_INJECTION"
    phase = "PROMPT"
    mode  = "BLOCK"
  }

  guardian {
    type  = "MODERATION"
    phase = "RESPONSE"
    mode  = "ALERT"
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name, active)
}

func testAccAiFirewallPolicyInvalidPhaseConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.application_id
  name           = "%s"

  guardian {
    type  = "PROMPT_INJECTION"
    phase = "RESPONSE"
    mode  = "BLOCK"
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name)
}

// aiFirewallPolicyImportID resolves the import key (policy UUID) for the named resource
// from Terraform state.
func aiFirewallPolicyImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}
		return rs.Primary.ID, nil
	}
}

func testAccCheckAiFirewallPolicyExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No policy ID is set")
		}

		client := testAccProvider.Meta().(*Client)

		policy, err := client.GetAiFirewallPolicy(aiFirewallTestAccountID(), rs.Primary.Attributes["application_id"], rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error getting AI Firewall policy: %s", err)
		}
		if policy == nil {
			return fmt.Errorf("AI Firewall policy %s not found", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckAiFirewallPolicyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "incapsula_ai_firewall_policy" {
			continue
		}
		if rs.Primary.ID == "" {
			continue
		}

		policy, err := client.GetAiFirewallPolicy(aiFirewallTestAccountID(), rs.Primary.Attributes["application_id"], rs.Primary.ID)
		if err == nil && policy != nil {
			return fmt.Errorf("AI Firewall policy still exists: %s", rs.Primary.ID)
		}
	}

	return nil
}
