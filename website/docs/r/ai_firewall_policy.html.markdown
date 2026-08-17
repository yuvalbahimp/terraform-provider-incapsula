---
subcategory: "AI Firewall"
layout: "incapsula"
page_title: "incapsula_ai_firewall_policy"
description: |-
  Provides an Imperva AI Firewall policy resource.
---

# incapsula_ai_firewall_policy

Provides an Imperva AI Firewall policy resource.

A policy holds a set of guardians that inspect traffic for an AI Firewall
application. Each guardian runs in a specific phase - `PROMPT` (the request sent to
the model) or `RESPONSE` (the model's reply) - and enforces an action (`BLOCK`,
`ALERT`, or `MASK`) when it triggers.

A policy is a child of an [`incapsula_ai_firewall_application`](ai_firewall_application.html.markdown);
the backend allows a single policy per application.

~> **Required guardian sets.** The backend enforces a *minimum* set of guardians per
deployment type and phase. A policy that omits any required guardian is rejected at
apply time with an `Invalid guardian set for '<type>' deployment in '<phase>' phase`
error listing the missing guardians. See
[Required guardians by deployment type](#required-guardians-by-deployment-type) below.

## Example Usage

The example below is a complete `SDK` policy: it includes the full required
guardian set for both phases. For `API` and `EDGE` the `RESPONSE` phase requires
fewer guardians (see the table below) - drop the `MODERATION` and
`SYSTEM_PROMPT_LEAK` guardians for those types.

```hcl
resource "incapsula_ai_firewall_application" "sdk_app" {
  account_id       = 1234567
  name             = "my-sdk-app"
  application_type = "SDK"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "sdk_policy" {
  account_id     = 1234567
  application_id = incapsula_ai_firewall_application.sdk_app.application_id
  name           = "default-policy"
  active         = true

  # --- PROMPT phase: SDK / API / EDGE all require these four ---
  guardian {
    type   = "PROMPT_INJECTION"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = jsonencode({
      threshold = 0.8
      message   = "Your request was blocked by the AI firewall."
    })
  }

  guardian {
    type   = "ZERO_SHOT_CLASSIFICATION"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = jsonencode({
      threshold  = 0.85
      categories = ["finance", "legal"]
      message    = "Your request was blocked by the AI firewall."
    })
  }

  guardian {
    type   = "PII_STATIC"
    phase  = "PROMPT"
    mode   = "ALERT"
    config = jsonencode({
      enabledPatterns = ["aws_access_key_id", "email_address"]
    })
  }

  guardian {
    type   = "RATE_LIMIT"
    phase  = "PROMPT"
    mode   = "BLOCK"
    config = jsonencode({
      globalConfig      = { enabled = true, maxTokens = 100000, timeUnitInSec = 60 }
      userConfig        = { enabled = true, maxTokens = 10000, timeUnitInSec = 60 }
      promptLimitConfig = { enabled = true, maxCharacters = 4000 }
      message           = "Rate limit exceeded."
    })
  }

  # --- RESPONSE phase: SDK requires all five (API / EDGE require only the first three) ---
  guardian {
    type   = "ZERO_SHOT_CLASSIFICATION"
    phase  = "RESPONSE"
    mode   = "BLOCK"
    config = jsonencode({
      threshold  = 0.9
      categories = ["finance", "legal"]
    })
  }

  guardian {
    type   = "PII_STATIC"
    phase  = "RESPONSE"
    mode   = "BLOCK"
    config = jsonencode({
      enabledPatterns = ["us_social_security_number"]
      message         = "Sensitive data was detected in the response."
    })
  }

  guardian {
    type   = "RATE_LIMIT"
    phase  = "RESPONSE"
    mode   = "ALERT"
    config = jsonencode({
      globalConfig      = { enabled = true, maxTokens = 200000, timeUnitInSec = 60 }
      userConfig        = { enabled = false, maxTokens = 20000, timeUnitInSec = 60 }
      promptLimitConfig = { enabled = true, maxCharacters = 8000 }
    })
  }

  # SDK only:
  guardian {
    type   = "MODERATION"
    phase  = "RESPONSE"
    mode   = "ALERT"
    config = jsonencode({ threshold = 0.8 })
  }

  guardian {
    type  = "SYSTEM_PROMPT_LEAK"
    phase = "RESPONSE"
    mode  = "BLOCK"
  }
}
```

## Argument Reference

The following arguments are supported:

* `account_id` - (Required) Numeric identifier of the account that owns the application. Cannot be changed after the resource is created.
* `application_id` - (Required) UUID of the AI Firewall application this policy belongs to. Cannot be changed after the resource is created.
* `name` - (Required) Name of the policy. 1-100 characters.
* `description` - (Optional) Description of the policy. Up to 500 characters.
* `active` - (Optional) Whether the policy is active. Default: `true`.
* `guardian` - (Required) One or more guardian blocks (at least one). Each block supports:
  * `type` - (Required) Guardian type. One of `PROMPT_INJECTION`, `PII_STATIC`, `MODERATION`, `ZERO_SHOT_CLASSIFICATION`, `RATE_LIMIT`, `SYSTEM_PROMPT_LEAK`.
  * `phase` - (Required) Phase the guardian runs in. One of `PROMPT`, `RESPONSE`. The valid phases depend on `type` (see below).
  * `mode` - (Required) Enforcement mode. One of `BLOCK`, `ALERT`, `MASK`.
  * `active` - (Optional) Whether this guardian is active. Default: `true`.
  * `config` - (Optional) Guardian-specific configuration as a JSON-encoded object. Default: `"{}"`. Use `jsonencode({...})`. See [Guardian config reference](#guardian-config-reference) for the fields each type accepts. Do **not** set a `type` key inside `config` - the provider injects the guardian's `type` automatically.

### Guardian type / phase compatibility

The valid `phase` values are constrained by the guardian `type`; an invalid
combination is rejected at plan time:

| Type | Allowed phases |
|------|----------------|
| `PROMPT_INJECTION` | `PROMPT` |
| `MODERATION` | `RESPONSE` |
| `SYSTEM_PROMPT_LEAK` | `RESPONSE` |
| `PII_STATIC` | `PROMPT`, `RESPONSE` |
| `RATE_LIMIT` | `PROMPT`, `RESPONSE` |
| `ZERO_SHOT_CLASSIFICATION` | `PROMPT`, `RESPONSE` |

### Required guardians by deployment type

In addition to the phase rules above, the backend requires a *complete* set of
guardians for each phase, and the required set depends on the application's
`application_type`. Include every guardian listed for your deployment type or the
apply fails.

| `application_type` | Required in `PROMPT` phase | Required in `RESPONSE` phase |
|--------------------|----------------------------|------------------------------|
| `SDK` | `PROMPT_INJECTION`, `ZERO_SHOT_CLASSIFICATION`, `PII_STATIC`, `RATE_LIMIT` | `ZERO_SHOT_CLASSIFICATION`, `MODERATION`, `PII_STATIC`, `RATE_LIMIT`, `SYSTEM_PROMPT_LEAK` |
| `API` | `PROMPT_INJECTION`, `ZERO_SHOT_CLASSIFICATION`, `PII_STATIC`, `RATE_LIMIT` | `ZERO_SHOT_CLASSIFICATION`, `PII_STATIC`, `RATE_LIMIT` |
| `EDGE` | `PROMPT_INJECTION`, `ZERO_SHOT_CLASSIFICATION`, `PII_STATIC`, `RATE_LIMIT` | `ZERO_SHOT_CLASSIFICATION`, `PII_STATIC`, `RATE_LIMIT` |

-> A guardian may be present but disabled by setting `active = false`; it still
counts toward the required set. This lets you satisfy the requirement while keeping
individual guardians switched off.

### Guardian config reference

The `config` object is a polymorphic structure whose accepted fields depend on the
guardian `type`. All types accept these **base** fields:

* `message` - (Optional) Custom message returned/logged when the guardian triggers.
* `exceptions` - (Optional) List of exception objects, each `{ id = "...", sentence = "..." }`, that suppress the guardian for specific phrases.

Type-specific fields:

| Type | Additional `config` fields |
|------|----------------------------|
| `PROMPT_INJECTION` | `threshold` (number 0-1, **required**) |
| `ZERO_SHOT_CLASSIFICATION` | `threshold` (number 0-1, **required**); `categories` (list of strings - the custom topics to classify against) |
| `MODERATION` | `threshold` (number 0-1, **required**); `categories` (list of strings) |
| `PII_STATIC` | `enabledPatterns` (list of PII pattern IDs to detect, e.g. `email_address`, `us_social_security_number`, `aws_access_key_id`) |
| `SYSTEM_PROMPT_LEAK` | none beyond the base fields |
| `RATE_LIMIT` | `globalConfig` and `userConfig`, each `{ enabled = bool, maxTokens = int (>= 1000), timeUnitInSec = int }`; `promptLimitConfig` `{ enabled = bool, maxCharacters = int (>= 256) }` |

## Attributes Reference

The following attributes are exported:

* `id` - The resource ID, equal to `policy_id`.
* `policy_id` - UUID of the policy.

## Import

AI Firewall policy can be imported using its `policy_id`:

```
$ terraform import incapsula_ai_firewall_policy.example 3f2504e0-4f89-41d3-9a0c-0305e82c3301
```

On import the `account_id` is taken from configuration on the following apply.