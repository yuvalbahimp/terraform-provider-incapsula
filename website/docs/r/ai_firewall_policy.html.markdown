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

## Example Usage

```hcl
resource "incapsula_ai_firewall_application" "app" {
  account_id       = 1234567
  name             = "my-api-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_policy" "policy" {
  account_id     = 1234567
  application_id = incapsula_ai_firewall_application.app.application_id
  name           = "default-policy"
  description    = "Baseline guardians for the API application"
  active         = true

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

  guardian {
    type   = "PII_STATIC"
    phase  = "RESPONSE"
    mode   = "MASK"
    config = jsonencode({ entities = ["EMAIL", "PHONE_NUMBER"] })
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
  * `config` - (Optional) Guardian-specific configuration as a JSON-encoded object. Default: `"{}"`. Use `jsonencode({...})`.

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