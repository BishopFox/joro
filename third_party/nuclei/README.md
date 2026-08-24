# nuclei — WAF signatures

The built-in WAF fingerprint rules in `internal/detect/rules_waf.go` are ported
from the **Global WAF Detect Matchers** template in the nuclei-templates project
by ProjectDiscovery.

- Upstream: https://github.com/projectdiscovery/nuclei-templates
- Template: `http/technologies/waf-detect.yaml` (global-matchers)
- License: MIT (see `LICENSE`)

Only the WAF regular expressions were used. They were adapted to the Joro detect
engine's rule model: one message part per rule, RE2 semantics, Info severity,
and a precision pass that dropped generic server-fingerprint entries and broad
non-vendor branches (details in the header of `rules_waf.go`). No nuclei code is
vendored.
