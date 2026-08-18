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
					resource.TestCheckResourceAttrSet(aiFirewallPolicyResourceName, "id"),
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

// TestAccIncapsulaAiFirewallPolicyConfigJSONIdempotent guards against the TypeSet + JSON
// config hashing trap: a guardian config written with keys in non-sorted order must not
// produce a perpetual diff. The backend (and flatten) round-trip config with sorted keys,
// so without the guardian set's normalized Set hash (aiFirewallGuardianHash) the refreshed
// set element would hash differently than the configured one and every plan would show a
// spurious guardian remove/add. The framework's automatic post-apply plan check fails if
// that regresses.
func TestAccIncapsulaAiFirewallPolicyConfigJSONIdempotent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallPolicyConfigJSONConfig("json-policy"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "1"),
				),
			},
			{
				// Re-applying the identical, non-sorted config must be a no-op.
				Config:             testAccAiFirewallPolicyConfigJSONConfig("json-policy"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccIncapsulaAiFirewallPolicyGuardianMutation is the positive control for the guardian
// set hashing / DiffSuppressFunc: it mutates a single guardian's config value, mode and
// active flag across a second apply and asserts each change actually lands in state. If the
// normalized-config Set hash (aiFirewallGuardianHash) or suppressor ever over-suppressed, a
// real edit would be silently dropped and these post-apply checks would fail.
func TestAccIncapsulaAiFirewallPolicyGuardianMutation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallPolicyGuardianMutationConfig("mut-policy", "BLOCK", true, `{"threshold":0.5}`),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(aiFirewallPolicyResourceName, "guardian.*", map[string]string{
						"type":   "PII_STATIC",
						"phase":  "PROMPT",
						"mode":   "BLOCK",
						"active": "true",
						"config": `{"threshold":0.5}`,
					}),
				),
			},
			{
				// Change config value + mode + active in one apply. Every field must round-trip.
				Config: testAccAiFirewallPolicyGuardianMutationConfig("mut-policy", "ALERT", false, `{"threshold":0.9}`),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(aiFirewallPolicyResourceName, "guardian.*", map[string]string{
						"type":   "PII_STATIC",
						"phase":  "PROMPT",
						"mode":   "ALERT",
						"active": "false",
						"config": `{"threshold":0.9}`,
					}),
				),
			},
		},
	})
}

// TestAccIncapsulaAiFirewallPolicyGuardianSetSize exercises guardian set cardinality changes:
// grow the set 1 -> 2 and shrink it back 2 -> 1, so expandAiFirewallGuardians /
// flattenAiFirewallGuardians round-trip as guardians are added and removed (and the request/
// response phase-split buckets grow and shrink) rather than only being mutated in place.
func TestAccIncapsulaAiFirewallPolicyGuardianSetSize(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallPolicyOneGuardianConfig("size-policy"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "1"),
				),
			},
			{
				// Add a second guardian (RESPONSE phase) -> set grows to 2.
				Config: testAccAiFirewallPolicyConfig("size-policy", true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "2"),
				),
			},
			{
				// Remove it again -> set shrinks back to 1.
				Config: testAccAiFirewallPolicyOneGuardianConfig("size-policy"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "1"),
				),
			},
		},
	})
}

// TestAccIncapsulaAiFirewallPolicyGuardianConfigDistinct declares two guardians that are
// identical except for their config JSON (same type/phase/mode/active), one carrying nested
// objects/arrays with non-sorted keys. It asserts (a) the Set hash keys off the normalized
// config so the two remain distinct elements (guardian.# == 2 rather than colliding to 1),
// and (b) re-applying the deeply-nested, non-sorted config is a no-op.
func TestAccIncapsulaAiFirewallPolicyGuardianConfigDistinct(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAiFirewallPolicyDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAiFirewallPolicyGuardianConfigDistinctConfig("distinct-policy"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAiFirewallPolicyExists(aiFirewallPolicyResourceName),
					resource.TestCheckResourceAttr(aiFirewallPolicyResourceName, "guardian.#", "2"),
					// The nested config round-trips into a distinct set element intact. State
					// keeps the configured (raw) string — the diff against the backend's sorted
					// form is absorbed by DiffSuppressFunc, while aiFirewallGuardianHash normalizes
					// before hashing so the two guardians stay distinct and stable.
					resource.TestCheckTypeSetElemNestedAttrs(aiFirewallPolicyResourceName, "guardian.*", map[string]string{
						"config": `{"nested":{"b":2,"a":1},"arr":[3,1,2]}`,
					}),
				),
			},
			{
				// Re-applying the identical, non-sorted, nested config must be a no-op.
				Config:             testAccAiFirewallPolicyGuardianConfigDistinctConfig("distinct-policy"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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
  application_id = incapsula_ai_firewall_application.policy_app.id
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

// testAccAiFirewallPolicyConfigJSONConfig declares a guardian whose config JSON has multiple
// keys in deliberately non-sorted order, to exercise config normalization/hash stability.
func testAccAiFirewallPolicyConfigJSONConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.id
  name           = "%s"

  guardian {
    type   = "PROMPT_INJECTION"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = "{\"z_threshold\":0.9,\"a_enabled\":true}"
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name)
}

// testAccAiFirewallPolicyGuardianMutationConfig declares a single PII_STATIC/PROMPT guardian
// whose mode, active flag and config JSON are caller-controlled, so a step can mutate exactly
// one guardian in place and assert the change round-trips.
func testAccAiFirewallPolicyGuardianMutationConfig(name, mode string, active bool, config string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.id
  name           = "%s"

  guardian {
    type   = "PII_STATIC"
    phase  = "PROMPT"
    mode   = "%s"
    active = %t
    config = %q
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name, mode, active, config)
}

// testAccAiFirewallPolicyOneGuardianConfig declares a policy with a single guardian, used to
// grow/shrink the guardian set against the two-guardian testAccAiFirewallPolicyConfig.
func testAccAiFirewallPolicyOneGuardianConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.id
  name           = "%s"

  guardian {
    type  = "PROMPT_INJECTION"
    phase = "PROMPT"
    mode  = "BLOCK"
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name)
}

// testAccAiFirewallPolicyGuardianConfigDistinctConfig declares two guardians that differ ONLY
// by their config JSON (same type/phase/mode), one of which carries nested objects/arrays with
// deliberately non-sorted keys — exercising both config-based set distinctness and deep JSON
// normalization stability.
func testAccAiFirewallPolicyGuardianConfigDistinctConfig(name string) string {
	return fmt.Sprintf(`
resource "incapsula_ai_firewall_application" "policy_app" {
  account_id       = %d
  name             = "policy-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "test" {
  account_id     = %d
  application_id = incapsula_ai_firewall_application.policy_app.id
  name           = "%s"

  guardian {
    type   = "PII_STATIC"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = "{\"z_threshold\":0.9,\"a_enabled\":true}"
  }

  guardian {
    type   = "PII_STATIC"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = "{\"nested\":{\"b\":2,\"a\":1},\"arr\":[3,1,2]}"
  }
}
`, aiFirewallTestAccountID(), aiFirewallTestAccountID(), name)
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
  application_id = incapsula_ai_firewall_application.policy_app.id
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
