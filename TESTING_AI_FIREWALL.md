# Testing Guide — AI Firewall resources: `incapsula_ai_firewall_application` (AIFW-1111), `incapsula_ai_firewall_policy` (AIFW-973) & `incapsula_ai_firewall_api_key` (AIFW-974)

How to build and test the Terraform Provider locally. You do **NOT** need Pablo's
`tf-provider-incap-orch.sh` script — that script only automates the same
`make` build/install/test steps this repo already provides, and its clone step
could clobber your uncommitted branch. Use `make` directly instead.

> **Branch layout (stacked).** Each branch is built on top of the previous one:
> `feature/AIFW-1111-ai-firewall-applicatio` (application resource + `BaseURLAiFirewall`
> cleanup) → `feature/AIFW-973-ai-firewall-policy` (policy resource) →
> `feature/AIFW-974-ai-firewall-api-key` (API-key resource). So the AIFW-974 branch contains
> all three resources. Both **policy** and **api_key** belong to an **application**
> (`application_id`), so all three are tested together. Everything below covers all three.

Environment already verified: macOS `darwin_arm64`, Go 1.26.5, Terraform 1.5.7.
Makefile is already set to `OS_ARCH=darwin_arm64`.

---

## ⚠️ Known gotcha: the 30s test timeout (this is what "fails" first)

`make test` hard-codes `-timeout=30s`. Several **pre-existing** "bad connection"
tests (and our own `TestAiFirewallApplicationBadConnection`) deliberately hit an
unreachable host. Since the recent retry/backoff change (commits `d2db2996` /
`ce2f507e`), each failed call now retries 4× with exponential backoff
(~1+2+4+8s). Four CRUD calls ≈ 68s, which blows past 30s and **panics with
`test timed out after 30s`**.

**This is not a bug in your code.** All AI Firewall tests pass when given enough
time (see below). It affects the whole repo, not just this branch.

---

## Level 1 — Compile check (fastest)

```bash
cd ~/IdeaProjects/terraform-provider-incapsula
go build -o /tmp/tf-provider-buildcheck . && echo "BUILD OK"
```

## Level 2 — Unit tests against the mock server (real logic validation)

The repo ships a mock Imperva API server. It must be running in a second terminal.

**Terminal A — start the mock server:**
```bash
cd ~/IdeaProjects/terraform-provider-incapsula
make server            # listens on http://localhost:19443
```

**Terminal B — set mock env vars and run tests:**
```bash
cd ~/IdeaProjects/terraform-provider-incapsula
export INCAPSULA_API_ID=mock-api-id
export INCAPSULA_API_KEY=mock-api-key
export INCAPSULA_BASE_URL=http://localhost:19443
export INCAPSULA_BASE_URL_REV_2=http://localhost:19443
export INCAPSULA_BASE_URL_REV_3=http://localhost:19443
export INCAPSULA_BASE_URL_API=http://localhost:19443
export INCAPSULA_CUSTOM_TEST_DOMAIN=.mock.incaptest.com
```

### Run ONLY the AI Firewall tests (recommended while developing — with a real timeout)
```bash
go test -run 'AiFirewall' -timeout 300s -v ./incapsula
```
Expected: all `TestAiFirewallApplication*`, `TestAiFirewallPolicy*` **and** `TestAiFirewallApiKey*` PASS.
The three `*BadConnection` tests (`...Application`, `...Policy`, `...ApiKey`) take ~69s each
(retry/backoff) — that's normal.

> NOTE: The AI Firewall resource no longer has its own `base_url_ai_firewall` knob.
> It derives its URL from `base_url_api` + the `/ai-application-security` prefix (baked
> into the endpoint constant in `client_ai_firewall_application.go`). So there is no
> separate `INCAPSULA_BASE_URL_AI_FIREWALL` env var or `TestMissingBaseURLAiFirewall` test.

### Run the FULL suite (`make test` fails on the 30s timeout — use this instead)
```bash
go test -timeout=300s -parallel=4 ./...
```
i.e. same as `make test` but with a sane timeout. If you want `make test` to work
as-is, you'd have to raise `-timeout` in the Makefile `test:` target — don't commit
that unless the team wants it.

## Level 3 — Real `terraform plan/apply` against the live Imperva API

Build the binary and install it into Terraform's local plugin dir:
```bash
cd ~/IdeaProjects/terraform-provider-incapsula
make install
# drops binary at:
# ~/.terraform.d/plugins/registry.terraform.io/terraform-providers/incapsula/<VERSION>/darwin_arm64
```
> NOTE: Makefile `VERSION` and the `version` in your `.tf` MUST match. Makefile
> currently says `VERSION=3.39.0` but the CHANGELOG adds `3.40.0 (Unreleased)`.
> Decide on the version, and if bumping, also update `incapsula/client.go` (~line 27).

Create a scratch dir (OUTSIDE the repo) with `main.tf`.

> ⚠️ **Base URLs default to PROD.** The provider's `Config.Client()` runs an
> account-verification call at configure time using `base_url` (the v1
> `my.incapsula.com` endpoint). If you use **stage credentials** against the prod
> default, `terraform plan` fails before it ever reaches your resource with:
> `res: 9411, "Authentication missing or invalid"`.
> To test on stage you must override the base URLs (see the stage example below).

### Stage example (recommended for dev/testing)
Credentials are masked — fill in your own stage `api_id` / `api_key` / `account_id`.
```hcl
terraform {
  required_providers {
    incapsula = {
      source  = "registry.terraform.io/terraform-providers/incapsula"
      version = "3.39.0"   # must equal Makefile VERSION
    }
  }
}

provider "incapsula" {
  api_id  = "<STAGE_API_ID>"
  api_key = "<STAGE_API_KEY>"

  # Point every relevant endpoint at STAGE:
  base_url       = "https://my.impervaservices.com/api/prov/v1"   # account-check + v1 resources
  base_url_rev_2 = "https://my.impervaservices.com/api/prov/v2"   # v2 resources
  base_url_api   = "https://api.stage.impervaservices.com"        # api.imperva resources, incl. AI Firewall
}

# Simplest case — SDK app (no configuration block needed)
resource "incapsula_ai_firewall_application" "sdk_app" {
  account_id       = <STAGE_ACCOUNT_ID>
  name             = "yuval-test-sdk-app"
  application_type = "SDK"
  region           = "US"
}

# A policy is scoped to an application via application_id.
resource "incapsula_ai_firewall_policy" "sdk_policy" {
  account_id     = <STAGE_ACCOUNT_ID>
  application_id = incapsula_ai_firewall_application.sdk_app.id
  name           = "yuval-test-policy"
  active         = true

  guardian {
    type  = "PROMPT_INJECTION"   # PROMPT-only
    phase = "PROMPT"
    mode  = "BLOCK"              # BLOCK | ALERT | MASK
  }

  guardian {
    type  = "MODERATION"         # RESPONSE-only
    phase = "RESPONSE"
    mode  = "ALERT"
    # config is an optional JSON string, defaults to "{}". Key order is not
    # significant — the guardian set is hashed on the normalized (canonical-JSON)
    # config, so re-applying the same object with keys in a different order is a
    # no-op (see aiFirewallGuardianHash / the JSON-idempotency acceptance test):
    # config = jsonencode({ threshold = 0.8 })
  }
}

# An API key is also scoped to an application. All inputs are immutable (ForceNew) and there
# is no update — changing name/app replaces the key. The plaintext key is returned ONCE.
resource "incapsula_ai_firewall_api_key" "sdk_key" {
  account_id     = <STAGE_ACCOUNT_ID>
  application_id = incapsula_ai_firewall_application.sdk_app.id
  name           = "yuval-test-key"   # 1-50 chars, [a-zA-Z0-9_-]
}

output "app_id" {
  value = incapsula_ai_firewall_application.sdk_app.id
}

output "policy_id" {
  value = incapsula_ai_firewall_policy.sdk_policy.id
}

output "api_key" {
  value     = incapsula_ai_firewall_api_key.sdk_key.api_key   # sensitive — plaintext, create-time only
  sensitive = true
}
```

> **`account_id` is optional** on all three resources. When omitted it defaults to the
> account of the API credentials. It is `ForceNew` (changing it replaces the resource).

> **API-key caveats.** `api_key` (plaintext) is **sensitive** and returned **only once, on
> create** — it is unrecoverable afterward and is **empty after import**. Read it via
> `terraform output -raw api_key` right after `apply`. The resource has **no update**: every
> attribute is `ForceNew`, so any change destroys and recreates the key. The only exported
> attributes are `id`, `api_key` and `active` (the UI-only `masked_api_key`, `created_at`,
> `last_used_at` and the redundant `api_key_id` were removed — the resource ID is `id`).

> **Guardian type ↔ phase rules (validated at plan time).** Declaring a guardian in a phase it
> doesn't support fails *before* any API call (via `CustomizeDiff`):
>
> | Guardian `type` | Allowed `phase`(s) |
> |-----------------|--------------------|
> | `PROMPT_INJECTION` | `PROMPT` |
> | `MODERATION` | `RESPONSE` |
> | `SYSTEM_PROMPT_LEAK` | `RESPONSE` |
> | `PII_STATIC` | `PROMPT`, `RESPONSE` |
> | `RATE_LIMIT` | `PROMPT`, `RESPONSE` |
> | `ZERO_SHOT_CLASSIFICATION` | `PROMPT`, `RESPONSE` |
>
> `mode` is one of `BLOCK` / `ALERT` / `MASK`. At least one `guardian` block is required.

### Prod example
Drop all the `base_url*` overrides (they default to prod) and use prod creds.
Credentials are masked — fill in your own prod `api_id` / `api_key` / `account_id`.
```hcl
terraform {
  required_providers {
    incapsula = {
      source  = "registry.terraform.io/terraform-providers/incapsula"
      version = "3.39.0"   # must equal Makefile VERSION
    }
  }
}

provider "incapsula" {
  api_id  = "<PROD_API_ID>"
  api_key = "<PROD_API_KEY>"
  # No base_url* overrides — the provider defaults to prod:
  #   base_url       = "https://my.incapsula.com/api/prov/v1"
  #   base_url_rev_2 = "https://my.imperva.com/api/prov/v2"
  #   base_url_api   = "https://api.imperva.com"   # AI Firewall = base_url_api + "/ai-application-security"
}

# Simplest case — SDK app (no configuration block needed)
resource "incapsula_ai_firewall_application" "sdk_app" {
  account_id       = <PROD_ACCOUNT_ID>
  name             = "yuval-test-sdk-app"
  application_type = "SDK"
  region           = "US"
}

output "app_id" {
  value = incapsula_ai_firewall_application.sdk_app.id
}
```

```bash
terraform init      # picks up the local plugin -> "Installed ... v3.39.0 (unauthenticated)"
terraform plan
terraform apply
terraform destroy   # clean up
```

> TIP: To keep secrets out of `main.tf` and state, omit `api_id`/`api_key` from the
> provider block and export `INCAPSULA_API_ID` / `INCAPSULA_API_KEY` instead. The
> base URLs can likewise be set via `INCAPSULA_BASE_URL`, `INCAPSULA_BASE_URL_REV_2`,
> `INCAPSULA_BASE_URL_API` (the AI Firewall resource uses `INCAPSULA_BASE_URL_API`).

## Level 4 — Acceptance tests

These drive the **real Terraform lifecycle engine** (not raw client calls).

**Application** — four tests, covering all application types and the nested `configuration` sub-resource:

| Test | Type | Covers |
|------|------|--------|
| `TestAccIncapsulaAiFirewallApplicationBasic`            | **API**  | create → update (rename + region, PATCH) → import (`ImportStateVerify`) → `CheckDestroy` |
| `TestAccIncapsulaAiFirewallApplicationEdge`             | **EDGE** | create with full nested `configuration` (incl. `request{}`/`response{}`) → PATCH a nested field → import (`ImportStateVerify`) → `CheckDestroy` |
| `TestAccIncapsulaAiFirewallApplicationEdgePartialConfig` | **EDGE** | `configuration` with a `request{}` block but **no** `response{}` — asserts `configuration.0.response.# == 0` (no phantom empty block) and round-trips via `ImportStateVerify`, guarding the flatten of an absent nested sub-block |
| `TestAccIncapsulaAiFirewallApplicationConfigValidation` | SDK/EDGE | plan-time validation: config **required** for EDGE, **rejected** for SDK |

**Policy** — six tests (each provisions an `incapsula_ai_firewall_application` first, since a policy needs an `application_id`). The `guardian` block is a `TypeSet`, so several of these specifically exercise its expand/flatten and its normalized-config Set hash (`aiFirewallGuardianHash`):

| Test | Covers |
|------|--------|
| `TestAccIncapsulaAiFirewallPolicyBasic`       | create (2 guardians) → update (rename + toggle `active`, PATCH) → import (`ImportStateVerify`, by policy UUID) → `CheckDestroy` |
| `TestAccIncapsulaAiFirewallPolicyInvalidPhase` | plan-time type/phase validation: `PROMPT_INJECTION` in the `RESPONSE` phase must error before any API call |
| `TestAccIncapsulaAiFirewallPolicyConfigJSONIdempotent` | guards the TypeSet + JSON-config hashing trap: a guardian `config` written with keys in non-sorted order must round-trip as a **no-op** (`PlanOnly` + `ExpectNonEmptyPlan: false`). Regresses if `aiFirewallGuardianHash` stops normalizing the config. |
| `TestAccIncapsulaAiFirewallPolicyGuardianMutation` | **positive control** for the config Set hash / `DiffSuppressFunc`: mutate a single guardian's `config` value + `mode` + `active` and assert each change lands in state (proves real edits are **not** over-suppressed) |
| `TestAccIncapsulaAiFirewallPolicyGuardianSetSize` | guardian set cardinality: grow `1 → 2` then shrink `2 → 1`, exercising expand/flatten as guardians are added/removed across the request/response phase buckets |
| `TestAccIncapsulaAiFirewallPolicyGuardianConfigDistinct` | two guardians identical except `config` (one with nested objects/arrays, non-sorted keys): asserts the Set hash keeps them **distinct** (`guardian.# == 2`) and re-applying the deep/nested config is a no-op |

**API key** — one test (provisions an `API`-type application first):

| Test | Covers |
|------|--------|
| `TestAccIncapsulaAiFirewallApiKeyBasic` | create (asserts the plaintext `api_key` and `id` are set) → import (`ImportStateVerify` by numeric key ID, with `ImportStateVerifyIgnore: ["api_key"]` since plaintext can't be recovered) → `CheckDestroy`. No update step — the resource is create/delete only. |

Two assertions worth calling out (vs. manual CLI runs):
* `ImportStateVerify: true` — byte-for-byte compares every attribute after import vs. the
  live resource. Best catch for read/flatten mismatches — especially in the EDGE test,
  where it validates the nested `configuration` `expand`/`flatten` round-trips.
* `CheckDestroy` — programmatically GETs after teardown to confirm the app is really gone.

### Coverage note (why EDGE was added)
Manual CLI testing only covered **SDK**, and the original acceptance test only covered
**API** (structurally identical to SDK — flat, no `configuration`). The **EDGE** path is the
only one with a nested `configuration` block, so `expandAiFirewallApplicationConfig` /
`flattenAiFirewallApplicationConfig` were previously untested. `TestAccIncapsulaAiFirewallApplicationEdge`
plus the validation test close that gap. All types are now covered.

### Naming convention
HCL resource addresses are only `type.name` (two parts), so the type is encoded in the
**local name**: `incapsula_ai_firewall_application.api_test`,
`...edge_test`, `...sdk_test`.

### They already passed against the mock
`TF_ACC=1` only changes *which* endpoint the test hits (via `INCAPSULA_BASE_URL*`), not the
test logic. All ten acceptance tests **already ran and passed** against the mock server:
```
--- PASS: TestAccIncapsulaAiFirewallApplicationBasic (0.93s)
--- PASS: TestAccIncapsulaAiFirewallApplicationEdge (0.92s)
--- PASS: TestAccIncapsulaAiFirewallApplicationEdgePartialConfig (0.60s)
--- PASS: TestAccIncapsulaAiFirewallApplicationConfigValidation (0.13s)
--- PASS: TestAccIncapsulaAiFirewallPolicyBasic (0.96s)
--- PASS: TestAccIncapsulaAiFirewallPolicyInvalidPhase (0.10s)
--- PASS: TestAccIncapsulaAiFirewallPolicyConfigJSONIdempotent (0.67s)
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianMutation (0.83s)
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianSetSize (1.17s)
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianConfigDistinct (0.68s)
--- PASS: TestAccIncapsulaAiFirewallApiKeyBasic (0.58s)
```

### Run it against STAGE (recommended — NOT prod)
"Acceptance test" does not mean "must hit prod." Point the env vars at stage and it exercises
the full framework with zero prod risk:
```bash
export INCAPSULA_API_ID=<STAGE_API_ID>
export INCAPSULA_API_KEY=<STAGE_API_KEY>
export INCAPSULA_BASE_URL=https://my.impervaservices.com/api/prov/v1
export INCAPSULA_BASE_URL_REV_2=https://my.impervaservices.com/api/prov/v2
export INCAPSULA_BASE_URL_API=https://api.stage.impervaservices.com   # AI Firewall derives from this
# Account the creds are scoped to (defaults to 1234 for the mock; REQUIRED for live backends):
export INCAPSULA_AI_FIREWALL_ACCOUNT_ID=<YOUR_STAGE_ACCOUNT_ID>
# Real site under that account, for the EDGE test (defaults to 987654 for the mock; REQUIRED for live):
export INCAPSULA_AI_FIREWALL_SITE_ID=<YOUR_STAGE_SITE_ID>
# Runs BOTH the application and policy acceptance tests:
TF_ACC=1 go test -run 'TestAccIncapsulaAiFirewall' -v -timeout 120m ./incapsula
```
> The **policy** and **api_key** tests only need `INCAPSULA_AI_FIREWALL_ACCOUNT_ID` (they each
> provision an `API`-type application, which needs no site). `INCAPSULA_AI_FIREWALL_SITE_ID`
> is required only by the application **EDGE** test. To run a single resource's tests:
> `-run 'TestAccIncapsulaAiFirewallPolicy'` or `-run 'TestAccIncapsulaAiFirewallApiKey'`.
> ⚠️ **Live-backend prerequisites (no source edits needed — all env-driven).** The test
> configs use mock-friendly defaults that a real backend rejects. Override via env vars:
>
> | Env var | Default (mock) | Why the live backend needs it |
> |---------|----------------|-------------------------------|
> | `INCAPSULA_AI_FIREWALL_ACCOUNT_ID` | `1234` | Else `401 / errCode 1003 Unauthorized request for account: 1234` |
> | `INCAPSULA_AI_FIREWALL_SITE_ID`    | `987654` | Else `400 Site ID 987654 does not exist for account …` (EDGE test only) |
>
> Also note the EDGE `blocked_response_structure` **must contain the `$BLOCKED_MESSAGE`
> placeholder** — the backend rejects it otherwise (`400 … must contain the $BLOCKED_MESSAGE
> placeholder`). The committed test already satisfies this.
>
> To run ONLY the account-scope-independent test first, target the API case:
> `-run 'TestAccIncapsulaAiFirewallApplicationBasic'` (needs only `ACCOUNT_ID`, no site).

### Can I skip it?
* **Skip** if your manual stage lifecycle already included an **import that showed no diff**
  and a **`plan`/GET after destroy** confirming the app is gone — that manually covers what
  this test asserts, and the mock run already proved the logic.
* **Don't skip** if your repo's CI/PR checks gate merges on `testacc`, or if you did NOT
  manually do the import + post-destroy verification.

### Prod (only if explicitly required — creates real billable resources)
Same command, but export the prod creds and drop the `INCAPSULA_BASE_URL*` overrides so it
uses the prod defaults. Use sparingly.

---

## Quick reference — files that make up these resources
| File | Purpose |
|------|---------|
| `incapsula/resource_ai_firewall_application.go`      | Application resource (schema + CRUD) |
| `incapsula/resource_ai_firewall_application_test.go` | Application acceptance tests |
| `incapsula/client_ai_firewall_application.go`        | Application API client calls |
| `incapsula/client_ai_firewall_application_test.go`   | Application client unit tests |
| `incapsula/mock_server_ai_firewall.go`               | Application mock server handlers |
| `incapsula/resource_ai_firewall_policy.go`           | Policy resource (schema + CRUD + guardian expand/flatten + plan-time phase validation) |
| `incapsula/resource_ai_firewall_policy_test.go`      | Policy acceptance tests |
| `incapsula/client_ai_firewall_policy.go`             | Policy API client calls |
| `incapsula/client_ai_firewall_policy_test.go`        | Policy client unit tests |
| `incapsula/mock_server_ai_firewall_policy.go`        | Policy mock server handlers (wired in `mock_server.go`) |
| `incapsula/resource_ai_firewall_api_key.go`          | API-key resource (schema + create/read/delete; all inputs ForceNew) |
| `incapsula/resource_ai_firewall_api_key_test.go`     | API-key acceptance test |
| `incapsula/client_ai_firewall_api_key.go`            | API-key API client calls |
| `incapsula/client_ai_firewall_api_key_test.go`       | API-key client unit tests |
| `incapsula/mock_server_ai_firewall_api_key.go`       | API-key mock server handlers (wired in `mock_server.go`) |
| `incapsula/provider.go`                              | Resource registration (all use `base_url_api`) |
| `incapsula/operation_constants.go`                   | CRUD operation constants (application + policy + api_key) |
| `website/docs/r/ai_firewall_application.html.markdown` | Application docs |
| `website/docs/r/ai_firewall_policy.html.markdown`      | Policy docs |
| `website/docs/r/ai_firewall_api_key.html.markdown`     | API-key docs |
| `CHANGELOG.md`                                       | `3.40.0 (Unreleased)` entry |

> Endpoints (all derive from `base_url_api`):
> - Application: `/ai-application-security/v3/api/applications`
> - Policy: `/ai-application-security/v3/applications/{applicationId}/policies`
> - API key: create/delete `/ai-application-security/v3/applications/{applicationId}/api-keys`;
>   read/list (account-level, used by import) `/ai-application-security/v3/api-keys`

## Last verified run (all pass)
```
# Client unit tests — application
--- PASS: TestAiFirewallApplicationBadConnection (68.82s)
--- PASS: TestAiFirewallApplicationCreate
--- PASS: TestAiFirewallApplicationRead
--- PASS: TestAiFirewallApplicationReadEmptyList
--- PASS: TestAiFirewallApplicationReadNotFound
--- PASS: TestAiFirewallApplicationUpdate
--- PASS: TestAiFirewallApplicationDelete
--- PASS: TestAiFirewallApplicationErrorResponse
--- PASS: TestMissingBaseURLAPI

# Client unit tests — policy
--- PASS: TestAiFirewallPolicyBadConnection (~69s)
--- PASS: TestAiFirewallPolicyCreate
--- PASS: TestAiFirewallPolicyCreateError
--- PASS: TestAiFirewallPolicyRead
--- PASS: TestAiFirewallPolicyReadNotFound
--- PASS: TestAiFirewallPolicyUpdate
--- PASS: TestAiFirewallPolicyDelete
--- PASS: TestAiFirewallPolicyErrorResponse

# Client unit tests — api_key
--- PASS: TestAiFirewallApiKeyBadConnection (~69s)
--- PASS: TestAiFirewallApiKeyCreate
--- PASS: TestAiFirewallApiKeyCreateMaxLimitError
--- PASS: TestAiFirewallApiKeyRead
--- PASS: TestAiFirewallApiKeyReadNotFound
--- PASS: TestAiFirewallApiKeyReadHttp404
--- PASS: TestAiFirewallApiKeyDelete
--- PASS: TestAiFirewallApiKeyErrorResponse

# Acceptance tests (TF_ACC=1, against mock server)
--- PASS: TestAccIncapsulaAiFirewallApplicationBasic (0.93s)             # API
--- PASS: TestAccIncapsulaAiFirewallApplicationEdge (0.92s)             # EDGE (full nested configuration)
--- PASS: TestAccIncapsulaAiFirewallApplicationEdgePartialConfig (0.60s) # EDGE config with request{} only, no response{}
--- PASS: TestAccIncapsulaAiFirewallApplicationConfigValidation (0.13s) # SDK/EDGE validation
--- PASS: TestAccIncapsulaAiFirewallPolicyBasic (0.96s)                 # policy lifecycle + import
--- PASS: TestAccIncapsulaAiFirewallPolicyInvalidPhase (0.10s)          # plan-time type/phase validation
--- PASS: TestAccIncapsulaAiFirewallPolicyConfigJSONIdempotent (0.67s)  # guardian JSON-config hash stability (no perpetual diff)
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianMutation (0.83s)      # guardian config/mode/active change applied (not over-suppressed)
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianSetSize (1.17s)       # guardian set grow 1->2 and shrink 2->1
--- PASS: TestAccIncapsulaAiFirewallPolicyGuardianConfigDistinct (0.68s) # distinct-by-config guardians + nested-JSON idempotency
--- PASS: TestAccIncapsulaAiFirewallApiKeyBasic (0.58s)                 # api_key create + import (ignore plaintext)
ok  github.com/terraform-providers/terraform-provider-incapsula/incapsula
```