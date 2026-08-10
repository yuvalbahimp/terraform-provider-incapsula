package incapsula

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const aiFirewallApplicationResourceName = "incapsula_ai_firewall_application.test"

// TestAccIncapsulaAiFirewallApplicationBasic exercises the full resource lifecycle
// against the mock server: create -> read -> update (name + region via PATCH) ->
// import (ImportStateVerify) -> destroy.
func TestAccIncapsulaAiFirewallApplicationBasic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallApplicationDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallApplicationConfig("my-app", "US"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationResourceName, "name", "my-app"),
					resource.TestCheckResourceAttr(aiFirewallApplicationResourceName, "application_type", "API"),
					resource.TestCheckResourceAttr(aiFirewallApplicationResourceName, "region", "US"),
					resource.TestCheckResourceAttrSet(aiFirewallApplicationResourceName, "application_id"),
					resource.TestCheckResourceAttrSet(aiFirewallApplicationResourceName, "status"),
				),
			},
			{
				Config: testAccAiFirewallApplicationConfig("renamed-app", "EU"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallApplicationExists(aiFirewallApplicationResourceName),
					resource.TestCheckResourceAttr(aiFirewallApplicationResourceName, "name", "renamed-app"),
					resource.TestCheckResourceAttr(aiFirewallApplicationResourceName, "region", "EU"),
				),
			},
			{
				ResourceName:      aiFirewallApplicationResourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs, ok := s.RootModule().Resources[aiFirewallApplicationResourceName]
					if !ok {
						return "", fmt.Errorf("Not found: %s", aiFirewallApplicationResourceName)
					}
					// Import key is the application UUID.
					return rs.Primary.ID, nil
				},
			},
		},
	})
}

func testAccAiFirewallApplicationConfig(name, region string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "test" {
  account_id       = 1234
  name             = "%s"
  application_type = "API"
  region           = "%s"
}
`, name, region)
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

		app, err := client.GetAiFirewallApplication(1234, rs.Primary.ID)
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

		app, err := client.GetAiFirewallApplication(1234, rs.Primary.ID)
		if err == nil && app != nil {
			return fmt.Errorf("AI Firewall application still exists: %s", rs.Primary.ID)
		}
	}

	return nil
}
