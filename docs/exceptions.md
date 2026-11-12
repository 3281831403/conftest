# Exceptions

There might be cases where rules might not apply under certain circumstances.
For those occasions, you can use `exceptions`. Exceptions are also written in
rego, and allow you to specify policies for when a given `deny` or `violation`
rule does not apply.

Inputs matched by the `exception` will be exempted from the rules specified in
`rules`, prefixed by `deny_` or `violation_`:

```rego
exception contains rules if {
  # Logic

  rules := ["foo","bar"]
}
```

The above would provide an exception from `deny_foo` and `violation_foo` as well
as `deny_bar` and `violation_bar`.

Note that if you specify the empty string, the exception will match *all* rules
named `deny` or `violation`. It is recommended to use identifiers in your rule
names to allow for targeted exceptions.

## Reporting

Exceptions are reported as a separate tally in Conftest's output, so you can
detect when exceptions are being made. For example, you might see this summary:

`2 tests, 1 passed, 0 warnings, 0 failures, 1 exception`.

The human readable output keeps the exception query string as the exception
message, e.g.:

`EXCP - examples/exceptions/deployments.yaml - main - data.main.exception[_][_] == "run_as_root"`

Structured output additionally records the violations that were waived so that
audits can see which rule was exempted and which messages it suppressed. In the
`json` output each exception carries `waived_rule`, `waived_severity`,
`waived_messages` and, when available, the full `waived_results` (including
locations) in its `metadata`:

```json
{
  "msg": "data.main.exception[_][_] == \"run_as_root\"",
  "metadata": {
    "waived_rule": "deny_run_as_root",
    "waived_severity": "failure",
    "waived_messages": [
      "Containers must not run as root in Deployment can-run-as-root"
    ],
    "waived_results": [
      {
        "msg": "Containers must not run as root in Deployment can-run-as-root",
        "metadata": {
          "query": "data.main.deny_run_as_root"
        }
      }
    ]
  }
}
```

In the `sarif` output each waived violation is reported against the rule that
produced it (preserving its message, level and location) and is marked with an
external `suppression` whose `justification` is the exception query string. The
invocation `exitCode` matches the process exit code, including the effects of
the `--fail-on-warn` and `--no-fail` flags.

## Examples

In the below example, a Kubernetes deployment named `can-run-as-root` will be
allowed to run as root, while others will not:

```rego
package main

deny_run_as_root contains msg if {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"
}

exception contains rules if {
  input.kind == "Deployment"
  input.metadata.name == "can-run-as-root"

  rules := ["run_as_root"]
}
```
