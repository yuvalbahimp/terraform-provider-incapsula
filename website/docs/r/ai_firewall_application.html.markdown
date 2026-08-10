---
subcategory: "AI Firewall"
layout: "incapsula"
page_title: "incapsula_ai_firewall_application"
description: |-
  Provides an Imperva AI Firewall application resource.
---

# incapsula_ai_firewall_application

Provides an Imperva AI Firewall application resource.

An AI Firewall application represents a protected AI/LLM endpoint. The deployment
type (`application_type`) determines how traffic reaches the application:

* `SDK` - traffic is inspected via the AI Firewall SDK integrated into your application.
* `API` - traffic is inspected via the AI Firewall API.
* `EDGE` - traffic is inspected inline at the edge. This type requires a
  `configuration` block describing how to extract prompts and responses.

## Example Usage

### SDK Application

```hcl
resource "incapsula_ai_firewall_application" "sdk_app" {
  account_id       = 1234567
  name             = "my-sdk-app"
  application_type = "SDK"
  region           = "US"
}
```

### API Application

```hcl
resource "incapsula_ai_firewall_application" "api_app" {
  account_id       = 1234567
  name             = "my-api-app"
  application_type = "API"
  region           = "EU"
}
```

### EDGE Application

An `EDGE` application requires a `configuration` block:

```hcl
resource "incapsula_ai_firewall_application" "edge_app" {
  account_id       = 1234567
  name             = "my-edge-app"
  application_type = "EDGE"
  region           = "US"

  configuration {
    site_id                    = 987654
    path                       = "/v1/chat/completions"
    content_type               = "application/json"
    prompt_location            = "$.messages[-1].content"
    blocked_response_structure = "{\"error\": \"blocked\"}"
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
```

## Argument Reference

The following arguments are supported:

* `account_id` - (Required) Numeric identifier of the account to operate on. Cannot be changed after the resource is created.
* `name` - (Required) Name of the AI Firewall application.
* `application_type` - (Required) Deployment type of the application. One of `SDK`, `EDGE`, `API`. Cannot be changed after the resource is created.
* `region` - (Optional) Data region of the application. One of `US`, `EU`, `AU`, `APAC`. If omitted, the application inherits the account's data region on create (the value is then stored as a computed attribute). Account-region inheritance is create-only: removing this attribute after it has been set does not revert to the account default - the last applied value is kept and the region is left unchanged. Set the attribute explicitly to move an application between regions.
* `configuration` - (Optional) Application configuration block. **Required** when `application_type = "EDGE"`; **not supported** for `SDK` or `API` application types. Supports a single block with the following arguments:
  * `site_id` - (Optional) Numeric identifier of the site the application is attached to.
  * `path` - (Optional) Request path to inspect.
  * `content_type` - (Optional) Content type of the inspected traffic. Default: `application/json`.
  * `prompt_location` - (Optional) Location of the prompt within the request payload.
  * `blocked_response_structure` - (Optional) Response body returned when a request is blocked.
  * `is_streaming` - (Optional) Whether the application uses streaming responses. Default: `false`.
  * `request` - (Optional) Single block describing how to extract fields from streaming requests:
    * `message_path` - (Optional) Path to the messages array.
    * `content_path` - (Optional) Path to the message content.
    * `role_path` - (Optional) Path to the message role.
  * `response` - (Optional) Single block describing how to extract fields from streaming responses:
    * `role_path` - (Optional) Path to the response role.
    * `content_path` - (Optional) Path to the response content.
    * `finish_reason_path` - (Optional) Path to the finish-reason field.
    * `finish_reason_value` - (Optional) Value of the finish-reason field that marks completion.
    * `end_of_stream_marker` - (Optional) Marker that signals the end of the stream.

## Attributes Reference

The following attributes are exported:

* `id` - The resource ID, equal to `application_id`.
* `application_id` - UUID of the application. Used as the import key and as `application_id` on the AI Firewall policy and api-key resources.
* `status` - Current status of the application. One of `CONFIGURED`, `ERROR`, `OPERATIONAL`.
* `status_description` - Description of the current status.

## Import

AI Firewall application can be imported using its `application_id`:

```
$ terraform import incapsula_ai_firewall_application.example 3f2504e0-4f89-41d3-9a0c-0305e82c3301
```