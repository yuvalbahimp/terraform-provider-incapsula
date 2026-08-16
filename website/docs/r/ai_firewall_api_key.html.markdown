---
subcategory: "AI Firewall"
layout: "incapsula"
page_title: "incapsula_ai_firewall_api_key"
description: |-
  Provides an Imperva AI Firewall API key resource.
---

# incapsula_ai_firewall_api_key

Provides an Imperva AI Firewall API key resource.

An API key authenticates client traffic to an AI Firewall application. The
plaintext key is returned **only once**, at creation time, in the sensitive
`api_key` attribute; it cannot be recovered afterward. Store it securely (for
example in Terraform state encrypted at rest, or pipe it straight into a secret
manager). After a `terraform import` the `api_key` attribute is empty because the
plaintext value is no longer retrievable from the backend.

An API key is a child of an [`incapsula_ai_firewall_application`](ai_firewall_application.html.markdown).
An account may hold at most **5** API keys; creation fails once that limit is
reached. All arguments are immutable - changing any of them forces a new resource
(the backend has no update endpoint for API keys).

## Example Usage

```hcl
resource "incapsula_ai_firewall_application" "app" {
  account_id       = 1234567
  name             = "my-api-app"
  application_type = "API"
  region           = "US"
}

resource "incapsula_ai_firewall_api_key" "key" {
  account_id     = 1234567
  application_id = incapsula_ai_firewall_application.app.application_id
  name           = "ci-pipeline-key"
}

output "ai_firewall_api_key" {
  value     = incapsula_ai_firewall_api_key.key.api_key
  sensitive = true
}
```

## Argument Reference

The following arguments are supported:

* `account_id` - (Required) Numeric identifier of the account that owns the application. Cannot be changed after the resource is created.
* `application_id` - (Required) UUID of the AI Firewall application this API key belongs to. Cannot be changed after the resource is created.
* `name` - (Required) Name of the API key. 1-50 characters; alphanumeric, underscore (`_`) or hyphen (`-`). Cannot be changed after the resource is created.

## Attributes Reference

The following attributes are exported:

* `id` - The resource ID, equal to `api_key_id`.
* `api_key_id` - Numeric ID of the API key.
* `api_key` - (Sensitive) The plaintext API key. Populated only on creation and unrecoverable afterward; empty after import.
* `masked_api_key` - The masked representation of the API key.
* `active` - Whether the API key is active.
* `created_at` - Creation time of the API key (epoch milliseconds).
* `last_used_at` - Last-used time of the API key (epoch milliseconds); `0` if never used.

## Import

AI Firewall API key can be imported using its `api_key_id`:

```
$ terraform import incapsula_ai_firewall_api_key.example 42
```

On import the `account_id` and `application_id` are taken from configuration on the
following apply, and the sensitive `api_key` attribute is empty (the plaintext key
is only ever returned at creation time).