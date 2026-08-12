package incapsula

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const aiFirewallApplicationApiResourceName = "incapsula_ai_firewall_application.api_test"
const aiFirewallApplicationEdgeResourceName = "incapsula_ai_firewall_application.edge_test"

// aiFirewallTestAccountID is the account the acceptance tests operate on. It defaults
// to 1234 (the mock server accepts any account), and is overridable via
// INCAPSULA_AI_FIREWALL_ACCOUNT_ID when running against a live stage/prod backend where
// the credentials are scoped to a specific account.
func aiFirewallTestAccountID() int {
	if v := os.Getenv("INCAPSULA_AI_FIREWALL_ACCOUNT_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			return id
		}
	}
	return 1234
}

// aiFirewallTestSiteID is the site the EDGE-type acceptance test attaches to. It defaults
// to 987654 (the mock server accepts any site), and is overridable via
// INCAPSULA_AI_FIREWALL_SITE_ID when running against a live backend, which validates that
// the site exists under the account.
func aiFirewallTestSiteID() int {
	if v := os.Getenv("INCAPSULA_AI_FIREWALL_SITE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			return id
		}
	}
	return 987654
}

// TestAccIncapsulaAiFirewallApplicationBasic exercises the full API-type resource
// lifecycle against the mock server: create -> read -> update (name + region via
// PATCH) -> import (ImportStateVerify) -> destroy.
func TestAccIncapsulaAiFirewallApplicationBasic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallApplicationDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallApplicationConfig("my-app", "US"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationApiResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "name", "my-app"),
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "application_type", "API"),
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "region", "US"),
					resource.TestCheckResourceAttrSet(aiFirewallApplicationApiResourceName, "application_id"),
					resource.TestCheckResourceAttrSet(aiFirewallApplicationApiResourceName, "status"),
					// API applications carry no configuration block.
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "configuration.#", "0"),
				),
			},
			{
				Config: testAccAiFirewallApplicationConfig("renamed-app", "EU"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationApiResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "name", "renamed-app"),
					resource.TestCheckResourceAttr(aiFirewallApplicationApiResourceName, "region", "EU"),
				),
			},
			{
				ResourceName:      aiFirewallApplicationApiResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: aiFirewallApplicationImportID(aiFirewallApplicationApiResourceName),
			},
		},
	})
}

// TestAccIncapsulaAiFirewallApplicationEdge exercises the EDGE-type resource, whose
// nested configuration block (site_id/path/prompt_location/is_streaming plus the
// nested request{} and response{} blocks) drives expandAiFirewallApplicationConfig
// and flattenAiFirewallApplicationConfig. The ImportStateVerify step compares every
// attribute after import against live state, so it is the strongest guard against a
// flatten mismatch in the nested blocks.
func TestAccIncapsulaAiFirewallApplicationEdge(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallApplicationDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallApplicationEdgeConfig("edge-app", "/v1/chat/completions"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationEdgeResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "name", "edge-app"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "application_type", "EDGE"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.#", "1"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.site_id", strconv.Itoa(aiFirewallTestSiteID())),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.path", "/v1/chat/completions"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.is_streaming", "true"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.request.#", "1"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.request.0.message_path", "$.messages"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.response.#", "1"),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.response.0.end_of_stream_marker", "[DONE]"),
				),
			},
			{
				// Mutate a nested configuration field -> PATCH carrying the whole config block.
				Config: testAccAiFirewallApplicationEdgeConfig("edge-app", "/v2/chat/completions"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationEdgeResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationEdgeResourceName, "configuration.0.path", "/v2/chat/completions"),
				),
			},
			{
				ResourceName:      aiFirewallApplicationEdgeResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: aiFirewallApplicationImportID(aiFirewallApplicationEdgeResourceName),
			},
		},
	})
}

// TestAccIncapsulaAiFirewallApplicationConfigValidation asserts the type<->configuration
// rules enforced by resourceAiFirewallApplicationCustomizeDiff: a configuration block is
// required for EDGE and rejected for SDK/API. Both errors surface at plan time, so no
// apply/backend call is needed.
func TestAccIncapsulaAiFirewallApplicationConfigValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				// EDGE without a configuration block must be rejected.
				Config:      testAccAiFirewallApplicationEdgeMissingConfig("edge-missing-config"),
				ExpectError: regexp.MustCompile("configuration is required for EDGE application type"),
			},
			{
				// SDK with a configuration block must be rejected.
				Config:      testAccAiFirewallApplicationSdkWithConfig("sdk-with-config"),
				ExpectError: regexp.MustCompile("configuration is not supported for SDK application type"),
			},
		},
	})
}

func testAccAiFirewallApplicationConfig(name, region string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "api_test" {
  account_id       = %d
  name             = "%s"
  application_type = "API"
  region           = "%s"
}
`, aiFirewallTestAccountID(), name, region)
}

func testAccAiFirewallApplicationEdgeConfig(name, path string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "edge_test" {
  account_id       = %d
  name             = "%s"
  application_type = "EDGE"
  region           = "US"

  configuration {
    site_id                    = %d
    path                       = "%s"
    content_type               = "application/json"
    prompt_location            = "$.messages[-1].content"
    blocked_response_structure = "{\"error\": \"$BLOCKED_MESSAGE\"}"
    is_streaming               = true

    request {
      message_path = "$.messages"
      content_path = "$.content"
      role_path    = "$.role"
    }

    response {
      role_path            = "$.choices[0].delta.role"
      content_path         = "$.choices[0].delta.content"
      finish_reason_path   = "$.choices[0].finish_reason"
      finish_reason_value  = "stop"
      end_of_stream_marker = "[DONE]"
    }
  }
}
`, aiFirewallTestAccountID(), name, aiFirewallTestSiteID(), path)
}

func testAccAiFirewallApplicationEdgeMissingConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "edge_test" {
  account_id       = %d
  name             = "%s"
  application_type = "EDGE"
  region           = "US"
}
`, aiFirewallTestAccountID(), name)
}

func testAccAiFirewallApplicationSdkWithConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "sdk_test" {
  account_id       = %d
  name             = "%s"
  application_type = "SDK"
  region           = "US"

  configuration {
    path = "/v1/chat/completions"
  }
}
`, aiFirewallTestAccountID(), name)
}

// aiFirewallApplicationImportID resolves the import key (application UUID) for the
// named resource from Terraform state.
func aiFirewallApplicationImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}
		return rs.Primary.ID, nil
	}
}

func testAccCheckAiFirewallApplicationExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No application ID is set")
		}

		client := testAccProvider.Meta().(*Client)

		app, err := client.GetAiFirewallApplication(aiFirewallTestAccountID(), rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Error getting AI Firewall application: %s", err)
		}
		if app == nil {
			return fmt.Errorf("AI Firewall application %s not found", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckAiFirewallApplicationDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "incapsula_ai_firewall_application" {
			continue
		}
		if rs.Primary.ID == "" {
			continue
		}

		app, err := client.GetAiFirewallApplication(aiFirewallTestAccountID(), rs.Primary.ID)
		if err == nil && app != nil {
			return fmt.Errorf("AI Firewall application still exists: %s", rs.Primary.ID)
		}
	}

	return nil
}