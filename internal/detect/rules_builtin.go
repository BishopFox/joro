package detect

// This file is the built-in rule library, exposed as a function rather than a
// package variable so nothing outside the engine can mutate the table.
//
// Every pattern must be valid RE2 — no lookahead, no lookbehind, no
// backreferences. Negative conditions belong in Rule.PostFilters.
//
// Conventions:
//   - IDs are stable kebab-case strings. Never rename one: Finding.RuleID and the
//     persisted disabled-rule set both reference it.
//   - Literal is a case-insensitive substring that must appear in any real match.
//     Getting it wrong silently disables the rule.
//   - Every shipped rule is enabled; there is no present-but-disabled tier.
//     A rule that cannot reach usable precision is not shipped.

// builtinRules returns a fresh copy of the shipped rule set.
func builtinRules() []Rule {
	var rules []Rule
	rules = append(rules, secretRules()...)
	rules = append(rules, piiRules()...)
	rules = append(rules, credentialRules()...)
	rules = append(rules, accessRules()...)
	rules = append(rules, disclosureRules()...)
	rules = append(rules, analyzerRules()...)
	return finalizeBuiltins(rules)
}

// finalizeBuiltins applies the shared defaults: built-in flag, regex kind,
// enabled, evidence grouping, and high confidence. Rules that differ set the
// field explicitly.
func finalizeBuiltins(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		r.Builtin = true
		if r.Kind == "" {
			r.Kind = KindRegex
		}
		if r.GroupBy == "" {
			r.GroupBy = GroupByEvidence
		}
		if r.Confidence == "" {
			r.Confidence = ConfidenceHigh
		}
		r.Enabled = true
		out[i] = r
	}
	return out
}

// Simplified content-type keywords used by Rule.ContentTypes and
// Rule.ExcludeContentTypes, matching the values contentTypeKeyword returns.
//
// There is no constant for "js": no rule may exclude JavaScript.
const (
	ctJSON  = "json"
	ctHTML  = "html"
	ctXML   = "xml"
	ctCSV   = "csv"
	ctPlain = "plain"
	ctCSS   = "css"
)

// secretRules covers provider-issued credentials, matched on a provider prefix
// plus a fixed-width body. Most need no post-filter.
func secretRules() []Rule {
	return []Rule{
		{
			ID: "aws-access-key-id", Name: "AWS access key ID",
			Description: "An AWS access key identifier. ASIA-prefixed keys are temporary STS credentials; AKIA are long-lived.",
			Remediation: "Rotate the key in IAM and remove it from the served content.",
			Category:    CategorySecrets, Severity: SeverityInfo,
			Target:         TargetResponseBody,
			Pattern:        `\b((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "aws-secret-access-key", Name: "AWS secret access key",
			Description: "A 40-character AWS secret access key adjacent to a key-name label. A bare 40-character base64 string is not matchable without flooding the results, so this rule requires the label.",
			Remediation: "Rotate the credential pair immediately and audit CloudTrail for use.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "secret",
			Pattern:        `(?i)\b(?:aws[_.-]?secret[_.-]?access[_.-]?key|aws[_.-]?secret|secretaccesskey)\b["'\s:=]{1,12}([A-Za-z0-9/+=]{40})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "aws-session-token", Name: "AWS session token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "token",
			Pattern:        `(?i)\b(?:aws[_.-]?session[_.-]?token|x-amz-security-token)\b["'\s:=]{1,12}([A-Za-z0-9/+=_-]{100,})`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "gcp-api-key", Name: "Google API key",
			Description: "A Google/Firebase API key. Browser-embedded Maps and Firebase keys are legitimately public — the finding is whether the key carries application and API restrictions.",
			Remediation: "Restrict the key by HTTP referrer and API in the Google Cloud console, or rotate it if unrestricted.",
			Category:    CategorySecrets, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "AIza",
			Pattern:        `\b(AIza[0-9A-Za-z_-]{35})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "gcp-service-account-json", Name: "GCP service account key file",
			Description: "A service-account JSON key including its private key material.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "service_account",
			Pattern:        `"type"\s*:\s*"service_account"`,
			MaxPerResponse: 1,
		},
		{
			ID: "gcp-oauth-client-secret", Name: "Google OAuth client secret",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "GOCSPX-",
			Pattern:        `\b(GOCSPX-[A-Za-z0-9_-]{28})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "google-oauth-refresh-token", Name: "Google OAuth refresh token",
			Category: CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "1//0",
			Pattern:        `\b(1//0[0-9A-Za-z_-]{20,})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "azure-storage-connection-string", Name: "Azure storage connection string",
			Description: "A storage account connection string including the shared account key. Evidence records the account name only.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "AccountKey=",
			Pattern:      `(?i)AccountName=([A-Za-z0-9]{3,24});AccountKey=[A-Za-z0-9+/=]{60,100}`,
			CaptureGroup: 1,
		},
		{
			ID: "azure-sas-token", Name: "Azure SAS token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "sig=",
			Pattern:        `(?i)\bsv=\d{4}-\d{2}-\d{2}[^"'\s]{0,200}?[?&]sig=([A-Za-z0-9%+/=]{20,})`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "azure-ad-client-secret", Name: "Azure AD client secret",
			Category: CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "secret",
			Pattern:      `(?i)\bclient[_-]?secret\b["'\s:=]{1,12}([A-Za-z0-9~._-]{32,44})\b`,
			CaptureGroup: 1, MinEntropy: 3.5,
			PostFilters:    []string{"denylist", "notHashLike"},
			RedactEvidence: true,
		},
		{
			ID: "github-pat", Name: "GitHub personal access token",
			Description: "A GitHub token. The prefix identifies the type: ghp classic PAT, gho OAuth, ghu user-to-server, ghs server-to-server, ghr refresh.",
			Remediation: "Revoke the token in GitHub settings and audit repository access.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "gh",
			Pattern:        `\b(gh[pousr]_[A-Za-z0-9]{36})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "github-fine-grained-pat", Name: "GitHub fine-grained PAT",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "github_pat_",
			Pattern:        `\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "slack-token", Name: "Slack API token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "xox",
			Pattern:        `\b(xox[baprse]-[0-9]{10,13}-[0-9A-Za-z-]{10,64})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "slack-app-token", Name: "Slack app-level token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "xapp-",
			Pattern:        `\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{64})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "slack-webhook-url", Name: "Slack incoming webhook URL",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "hooks.slack.com",
			Pattern:        `(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,28})`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "stripe-live-secret-key", Name: "Stripe live secret key",
			Description: "A live-mode Stripe secret or restricted key. Publishable keys (pk_live_) are intentionally public and are not reported.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "_live_",
			Pattern:        `\b((?:sk|rk)_live_[A-Za-z0-9]{20,99})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "twilio-auth-token", Name: "Twilio auth token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "twilio",
			Pattern:        `(?i)\btwilio[_-]?(?:auth[_-]?token|token|secret)\b["'\s:=]{1,12}([0-9a-f]{32})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "twilio-account-sid", Name: "Twilio account SID",
			Description: "An account identifier rather than a secret. Reported because it pairs with an auth token.",
			Category:    CategorySecrets, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "AC",
			Pattern:      `\b(AC[0-9a-fA-F]{32})\b`,
			CaptureGroup: 1,
		},
		{
			ID: "sendgrid-api-key", Name: "SendGrid API key",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "SG.",
			Pattern:        `\b(SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,64})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "mailgun-api-key", Name: "Mailgun API key",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "key-",
			Pattern:        `\bkey-([0-9a-f]{32})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "npm-token", Name: "npm access token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "npm_",
			Pattern:        `\b(npm_[A-Za-z0-9]{36})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "openai-api-key", Name: "OpenAI API key",
			Description: "An OpenAI secret key. The sk- prefix is generic enough to warrant medium confidence; note Stripe uses sk_ with an underscore.",
			Category:    CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "sk-",
			Pattern:        `\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "anthropic-api-key", Name: "Anthropic API key",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "sk-ant-",
			Pattern:        `\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "shopify-token", Name: "Shopify access token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "shp",
			Pattern:        `\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "square-access-token", Name: "Square access token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "sq0atp-",
			Pattern:        `\b(sq0atp-[A-Za-z0-9_-]{22})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "atlassian-api-token", Name: "Atlassian API token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "ATATT3",
			Pattern:        `\b(ATATT3[A-Za-z0-9_=-]{100,})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "telegram-bot-token", Name: "Telegram bot token",
			Category: CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: ":AA",
			Pattern:        `\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "datadog-api-key", Name: "Datadog API key",
			Category: CategorySecrets, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "dd",
			Pattern:        `(?i)\bdd[_-]?api[_-]?key\b["'\s:=]{1,12}([a-f0-9]{32})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "algolia-admin-key", Name: "Algolia admin API key",
			Category: CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "algolia",
			Pattern:        `(?i)\balgolia[_-]?(?:admin|api)[_-]?key\b["'\s:=]{1,12}([a-f0-9]{32})\b`,
			CaptureGroup:   1,
			RedactEvidence: true,
		},
		{
			ID: "private-key-pem", Name: "Private key PEM block",
			Description: "A PEM-encoded private key served in a response body. Evidence records the BEGIN line only.",
			Remediation: "Remove the key from the served path and rotate the key pair.",
			Category:    CategorySecrets, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "-----BEGIN",
			Pattern:        `-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |SSH2 )?PRIVATE KEY(?: BLOCK)?-----`,
			MaxPerResponse: 1,
		},
		{
			ID: "jwt-present", Name: "JSON Web Token",
			Description: "A JWT observed in traffic. Grouped per host because an authenticated session presents one on nearly every request.",
			Category:    CategorySecrets, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "eyJ",
			Pattern:      `\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`,
			CaptureGroup: 1, GroupBy: GroupByHost,
			PostFilters:    []string{"jwtStructure"},
			RedactEvidence: true,
		},
		{
			ID: "generic-api-key-assignment", Name: "Generic API key assignment",
			Description: "A key-like name assigned a high-entropy value. Ships enabled only because the entropy threshold and placeholder denylist suppress template values; without them this rule is unusable against a minified bundle.",
			Category:    CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `(?i)\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?token|bearer[_-]?token)\b\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{16,120})["']?`,
			CaptureGroup: 1, MinEntropy: 3.5, MinLength: 16,
			PostFilters:    []string{"denylist", "notHashLike"},
			RedactEvidence: true,
		},
		{
			ID: "generic-password-assignment", Name: "Generic password assignment",
			Description: "A password-like name assigned a literal value. Excludes JavaScript and CSS, where framework bundles produce constant noise.",
			Category:    CategorySecrets, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `(?i)\b(?:password|passwd|pwd|passphrase)\b\s*[:=]\s*["']([^"'\s]{6,80})["']`,
			CaptureGroup: 1, MaxPerResponse: 2,
			ContentTypes:   []string{ctHTML, ctJSON, ctXML, ctPlain},
			PostFilters:    []string{"denylist"},
			RedactEvidence: true,
		},
	}
}

// piiRules covers personal data. Every rule here carries at least one of: a
// checksum post-filter, a required label, or a content-type gate. Formats with
// neither a checksum nor a label are not shipped.
func piiRules() []Rule {
	return []Rule{
		{
			ID: "email-address", Name: "Email address",
			Description: "An email address in a structured response. Reported as info because an address in a JSON API response is usually intentional; the aggregate signal is the bulk-exposure analyzer.",
			Category:    CategoryPII, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "@",
			Pattern:      `\b([A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})\b`,
			CaptureGroup: 1, GroupBy: GroupByURL, MaxPerResponse: 3,
			ContentTypes: []string{ctJSON, ctXML, ctCSV, ctPlain},
			PostFilters:  []string{"denylist"},
		},
		{
			ID: "us-ssn-formatted", Name: "US Social Security number",
			Description: "A dash-formatted SSN whose area, group, and serial are all assignable. There is deliberately no unformatted variant: a bare nine-digit run matches timestamps and identifiers.",
			Category:    CategoryPII, Severity: SeverityCritical, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "-",
			Pattern:      `\b([0-8]\d{2}-\d{2}-\d{4})\b`,
			CaptureGroup: 1,
			ContentTypes: []string{ctJSON, ctXML, ctCSV, ctPlain},
			PostFilters:  []string{"ssn"}, RedactEvidence: true,
		},
		{
			ID: "us-ssn-labeled", Name: "Labeled US Social Security number",
			Category: CategoryPII, Severity: SeverityCritical,
			Target:       TargetResponseBody,
			Pattern:      `(?i)\b(?:ssn|social[_ -]?security(?:[_ -]?(?:number|no|num))?|tax[_ -]?id)\b[^0-9\n]{0,24}(\d{3}-?\d{2}-?\d{4})\b`,
			CaptureGroup: 1,
			// Excludes css rather than whitelisting formats, so the rule stays live
			// everywhere else, including .js bundles.
			ExcludeContentTypes: []string{ctCSS},
			PostFilters:         []string{"ssn"}, RedactEvidence: true,
		},
		{
			ID: "credit-card", Name: "Credit card number",
			Description: "A payment card number passing the Luhn checksum with a length matching its issuer. Published gateway test numbers are excluded.",
			Remediation: "Confirm whether the response should expose cardholder data; if so, mask all but the last four digits.",
			Category:    CategoryPII, Severity: SeverityCritical, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `\b((?:4\d{3}|5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)|3[47]\d{2}|6(?:011|5\d{2}|4[4-9]\d)|3(?:0[0-5]|[68]\d)\d)[ -]?\d{4}[ -]?\d{4}[ -]?\d{0,4})\b`,
			CaptureGroup: 1,
			ContentTypes: []string{ctJSON, ctXML, ctCSV, ctPlain, ctHTML},
			PostFilters:  []string{"luhn"}, RedactEvidence: true,
		},
		{
			ID: "iban", Name: "IBAN",
			Description: "An International Bank Account Number passing the ISO 13616 mod-97 check.",
			Category:    CategoryPII, Severity: SeverityCritical,
			Target:              TargetResponseBody,
			Pattern:             `\b([A-Z]{2}\d{2} ?(?:[A-Z0-9]{4} ?){2,7}[A-Z0-9]{1,4})\b`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS},
			PostFilters:         []string{"iban97"}, RedactEvidence: true,
		},
		{
			ID: "phone-labeled", Name: "Labeled phone number",
			Category: CategoryPII, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target:              TargetResponseBody,
			Pattern:             `(?i)\b(?:phone|mobile|cell|telephone|msisdn|fax)(?:[_ -]?number)?\b["'\s:=]{1,12}(\+?[0-9][0-9 ()\-.]{7,18}\d)`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS},
		},
		{
			ID: "date-of-birth-labeled", Name: "Labeled date of birth",
			Description: "A birth date next to an explicit label. Unlabeled dates are not honestly detectable, so no unlabeled variant exists.",
			Category:    CategoryPII, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target:              TargetResponseBody,
			Pattern:             `(?i)\b(?:dob|d\.o\.b|date[_ -]?of[_ -]?birth|birth[_ -]?date|birthday)\b["'\s:=]{1,16}([0-9]{1,4}[-/.][0-9]{1,2}[-/.][0-9]{1,4})`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS}, RedactEvidence: true,
		},
		{
			ID: "uk-national-insurance", Name: "UK National Insurance number",
			Category: CategoryPII, Severity: SeverityCritical, Confidence: ConfidenceMedium,
			Target:         TargetResponseBody,
			Pattern:        `\b([ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D])\b`,
			CaptureGroup:   1,
			ContentTypes:   []string{ctJSON, ctXML, ctCSV, ctPlain},
			RedactEvidence: true,
		},
		{
			ID: "nhs-number", Name: "NHS number",
			Description: "A UK NHS number passing the mod-11 check digit. Only shippable because of that checksum.",
			Category:    CategoryPII, Severity: SeverityCritical,
			Target:       TargetResponseBody,
			Pattern:      `\b(\d{3}[ -]?\d{3}[ -]?\d{4})\b`,
			CaptureGroup: 1,
			ContentTypes: []string{ctJSON, ctXML, ctCSV},
			PostFilters:  []string{"mod11nhs"}, RedactEvidence: true,
		},
		{
			ID: "cl-rut", Name: "Chilean RUT",
			Description: "A Chilean national tax and identity number, validated by its mod-11 check digit. The check digit is the whole precision mechanism, which is why no adjacent label is required.",
			Category:    CategoryPII, Severity: SeverityCritical,
			Target:       TargetResponseBody,
			Pattern:      `\b(\d{1,2}\.?\d{3}\.?\d{3}-[\dkK])\b`,
			CaptureGroup: 1,
			// HTML is included, as for credit-card and br-cpf: a RUT has a dotted
			// shape and a mod-11 check digit behind it.
			ContentTypes: []string{ctJSON, ctXML, ctCSV, ctPlain, ctHTML},
			PostFilters:  []string{"rutMod11"}, RedactEvidence: true,
		},
		{
			ID: "br-cpf", Name: "Brazilian CPF",
			Category: CategoryPII, Severity: SeverityCritical,
			Target:              TargetResponseBody,
			Pattern:             `\b(\d{3}\.\d{3}\.\d{3}-\d{2})\b`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS},
			PostFilters:         []string{"cpf"}, RedactEvidence: true,
		},
		{
			ID: "ca-sin-labeled", Name: "Labeled Canadian SIN",
			Category: CategoryPII, Severity: SeverityCritical, Confidence: ConfidenceMedium,
			Target:              TargetResponseBody,
			Pattern:             `(?i)\b(?:sin|social[_ -]?insurance)\b[^0-9\n]{0,20}(\d{3}[ -]?\d{3}[ -]?\d{3})\b`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS},
			PostFilters:         []string{"luhn"}, RedactEvidence: true,
		},
		{
			ID: "in-aadhaar-labeled", Name: "Labeled Aadhaar number",
			Category: CategoryPII, Severity: SeverityCritical, Confidence: ConfidenceMedium,
			Target: TargetResponseBody, Literal: "aadha",
			Pattern:             `(?i)\baadha?ar\b[^0-9\n]{0,20}(\d{4}[ -]?\d{4}[ -]?\d{4})\b`,
			CaptureGroup:        1,
			ExcludeContentTypes: []string{ctCSS},
			PostFilters:         []string{"verhoeff"}, RedactEvidence: true,
		},
		// No US driver's licence rule: fifty state formats with no checksum leave
		// label proximity as the only precision mechanism, which is not enough.
		{
			ID: "pii-in-url", Name: "Personal data in URL",
			Description: "Personal data in a query string leaks to access logs, Referer headers, and browser history regardless of TLS.",
			Remediation: "Move the parameter into a request body or a server-side session.",
			Category:    CategoryPII, Severity: SeverityHigh,
			Target: TargetURL, Literal: "=",
			Pattern:      `(?i)[?&]((?:e?mail|ssn|dob|birth[_-]?date|first[_-]?name|last[_-]?name|full[_-]?name|phone|mobile|passport|national[_-]?id|tax[_-]?id|card[_-]?number)=[^&\s#]{2,})`,
			CaptureGroup: 1, GroupBy: GroupByURL,
			RedactEvidence: true,
		},
	}
}

// credentialRules cover authentication material in transit and credential files
// served by mistake.
func credentialRules() []Rule {
	return []Rule{
		{
			ID: "basic-auth-in-url", Name: "Credentials in URL userinfo",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "://",
			Pattern:      `\b[a-z][a-z0-9+.\-]{1,20}://([^/\s:@"']{1,64}):[^/\s:@"']{1,64}@`,
			CaptureGroup: 1, RedactEvidence: true,
		},
		{
			ID: "auth-material-in-query-string", Name: "Authentication material in query string",
			Description: "A token, key, or password in a URL. Leaks to access logs, Referer headers, and browser history.",
			Remediation: "Move the credential into a header or request body.",
			Category:    CategoryCredentials, Severity: SeverityHigh,
			Target: TargetURL, Literal: "=",
			Pattern:      `(?i)[?&]((?:access_token|id_token|refresh_token|api[_-]?key|apikey|authorization|jwt|session_?id|password|passwd|pwd|secret)=[^&\s#]{8,})`,
			CaptureGroup: 1, GroupBy: GroupByURL,
			RedactEvidence: true,
		},
		{
			ID: "db-connection-string", Name: "Database connection string with password",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "://",
			Pattern:      `(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|rediss?|amqps?|clickhouse|cassandra)://([^\s"'<>]{1,64}):[^\s"'<>]{1,64}@([^\s"'<>/]{1,120})`,
			CaptureGroup: 0, RedactEvidence: true,
		},
		{
			ID: "ado-net-connection-string", Name: "ADO.NET connection string with password",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "=",
			Pattern:      `(?i)\b(?:server|data source|initial catalog)\s*=\s*[^;\n]{1,64};[^\n]{0,240}?\b(?:password|pwd)\s*=\s*([^;\s"'<]{1,64})`,
			CaptureGroup: 1, RedactEvidence: true,
		},
		{
			ID: "htpasswd-exposed", Name: "htpasswd file exposed",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "$",
			Pattern:      `(?m)^([A-Za-z0-9._-]{1,32}):\$(?:apr1|2[aby]|1|5|6)\$`,
			CaptureGroup: 1,
			PostFilters:  []string{"notHTML"},
		},
		{
			ID: "shadow-file-exposed", Name: "Unix shadow entry exposed",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseBody, Literal: "$",
			Pattern:      `(?m)^([A-Za-z0-9._-]{1,32}):[!*]?\$[16y5]\$[^:]{8,}:\d{4,5}:`,
			CaptureGroup: 1,
			PostFilters:  []string{"notHTML"},
		},
		{
			ID: "hardcoded-credential-pair", Name: "Hardcoded credential pair",
			Description: "A username and password assigned near each other. Requiring the pair is substantially more precise than matching a password alone.",
			Category:    CategoryCredentials, Severity: SeverityHigh, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `(?i)\b(?:user(?:name)?|login|uid|account)\b\s*[:=]\s*["']([^"'\s]{3,48})["'][\s\S]{0,120}?\b(?:password|passwd|pwd|secret)\b\s*[:=]\s*["'][^"'\s]{3,64}["']`,
			CaptureGroup: 1,
			PostFilters:  []string{"denylist"}, RedactEvidence: true,
		},
		{
			ID: "credentials-in-set-cookie", Name: "Credential in Set-Cookie",
			Category: CategoryCredentials, Severity: SeverityHigh,
			Target: TargetResponseHeader, Literal: "set-cookie",
			Pattern:      `(?im)^set-cookie:[^\n]{0,80}\b(?:pass(?:word)?|pwd|passwd|secret)=([^;\s]{3,})`,
			CaptureGroup: 1, GroupBy: GroupByHost,
			RedactEvidence: true,
		},
	}
}

// accessRules identify authentication surfaces and management consoles. Product
// fingerprints group per host.
func accessRules() []Rule {
	fingerprint := func(id, name string, sev Severity, target Target, literal, pattern string, group int) Rule {
		return Rule{
			ID: id, Name: name, Category: CategoryAccess, Severity: sev,
			Target: target, Literal: literal, Pattern: pattern,
			CaptureGroup: group, GroupBy: GroupByHost,
			StatusCodes: "200,401,403",
		}
	}
	return []Rule{
		{
			ID: "admin-panel-path", Name: "Administrative path",
			Description: "A URL path matching a common administrative or management route. Medium confidence because /dashboard and /console are also ordinary application routes.",
			Category:    CategoryAccess, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target: TargetURL, Literal: "/",
			Pattern:      `(?i)/(admin(?:istrator|_?panel|cp|login)?|wp-admin|manage(?:r|ment)?|console|cpanel|whm|plesk|webadmin|phpmyadmin|pma|adminer|sysadmin|backend|controlpanel|siteadmin|useradmin)(?:/|$|\?)`,
			CaptureGroup: 1, GroupBy: GroupByURL,
			StatusCodes: "200,301,302,401,403",
		},
		{
			ID: "http-auth-challenge", Name: "HTTP authentication challenge",
			Description: "A Basic or Digest challenge. The realm frequently names an internal system.",
			Category:    CategoryAccess, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "www-authenticate",
			Pattern:      `(?im)^www-authenticate:[ \t]*(basic|digest)(?:[ \t]+realm="([^"]{0,80})")?`,
			CaptureGroup: 0, GroupBy: GroupByHost,
			StatusCodes: "401",
		},
		{
			ID: "ntlm-negotiate-endpoint", Name: "Windows integrated authentication endpoint",
			Description: "An NTLM or Negotiate challenge, indicating a Windows-integrated application reachable here.",
			Category:    CategoryAccess, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "www-authenticate",
			Pattern: `(?im)^www-authenticate:[ \t]*(?:NTLM|Negotiate)`,
			GroupBy: GroupByHost, StatusCodes: "401",
		},
		{
			ID: "spring-actuator-open", Name: "Spring Boot Actuator exposed",
			Description: "An unauthenticated Actuator endpoint. /env, /heapdump, /jolokia, and /threaddump disclose credentials or memory contents.",
			Category:    CategoryAccess, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "_links",
			Pattern:     `"_links"\s*:\s*\{[\s\S]{0,999}?"(?:health|env|beans|heapdump|threaddump|configprops)"`,
			GroupBy:     GroupByHost,
			StatusCodes: "200",
		},
		{
			ID: "graphql-introspection", Name: "GraphQL introspection enabled",
			Description: "The schema is queryable, which hands an attacker the full API surface.",
			Remediation: "Disable introspection in production.",
			Category:    CategoryAccess, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "__schema",
			Pattern:     `"__schema"\s*:\s*\{[\s\S]{0,400}?"types"\s*:\s*\[`,
			GroupBy:     GroupByHost,
			StatusCodes: "200",
		},
		{
			ID: "swagger-openapi-exposed", Name: "API schema document exposed",
			Category: CategoryAccess, Severity: SeverityInfo,
			Target:      TargetResponseBody,
			Pattern:     `(?i)(?:swagger-ui|"swagger"\s*:\s*"2|"openapi"\s*:\s*"3)`,
			GroupBy:     GroupByURL,
			StatusCodes: "200",
		},
		{
			ID: "keycloak-realm-exposed", Name: "Keycloak realm metadata exposed",
			Category: CategoryAccess, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target: TargetURL, Literal: "realms/",
			Pattern:     `(?i)/(?:auth/)?realms/[^/]+/\.well-known/openid-configuration`,
			GroupBy:     GroupByHost,
			StatusCodes: "200",
		},
		{
			ID: "vpn-appliance-login", Name: "Remote-access appliance login",
			Description: "An internet-facing VPN or remote-access appliance portal. These are high-value targets and frequently unpatched.",
			Category:    CategoryAccess, Severity: SeverityInfo,
			Target:      TargetResponseBody,
			Pattern:     `(?i)(/dana-na/|Citrix Gateway|/remote/login\?lang=|Pulse Secure|GlobalProtect Portal|<title>\s*SonicWall)`,
			GroupBy:     GroupByHost,
			StatusCodes: "200",
		},
		fingerprint("phpmyadmin-exposed", "phpMyAdmin exposed", SeverityInfo, TargetResponseBody,
			"", `(?i)(?:<title>\s*phpMyAdmin|name="pma_username"|pmahomme)`, 0),
		fingerprint("adminer-exposed", "Adminer exposed", SeverityInfo, TargetResponseBody,
			"adminer", `(?i)<title>\s*(?:Login\s*-\s*)?Adminer\b`, 0),
		fingerprint("tomcat-manager-exposed", "Tomcat Manager exposed", SeverityInfo, TargetResponseBody,
			"", `(?i)(?:<title>/manager\b|Tomcat Web Application Manager|<title>Apache Tomcat/([0-9.]+))`, 0),
		fingerprint("jboss-wildfly-console", "JBoss/WildFly console exposed", SeverityInfo, TargetResponseBody,
			"console", `(?i)(?:JBoss AS Administration Console|WildFly Management Console)`, 0),
		fingerprint("weblogic-console", "WebLogic console exposed", SeverityInfo, TargetResponseBody,
			"weblogic", `(?i)<title>\s*Oracle WebLogic Server Administration Console`, 0),
		fingerprint("websphere-console", "WebSphere console exposed", SeverityInfo, TargetResponseBody,
			"websphere", `(?i)WebSphere Integrated Solutions Console`, 0),
		fingerprint("rabbitmq-management", "RabbitMQ management exposed", SeverityInfo, TargetResponseBody,
			"rabbitmq", `(?i)RabbitMQ Management`, 0),
		fingerprint("jupyter-exposed", "Jupyter exposed", SeverityInfo, TargetResponseBody,
			"jupyter", `(?i)(?:<title>\s*Jupyter\b|jupyter-config-data)`, 0),
		fingerprint("elasticsearch-exposed", "Elasticsearch exposed", SeverityInfo, TargetResponseBody,
			"lucene_version", `"cluster_name"\s*:[\s\S]{0,400}?"lucene_version"\s*:`, 0),
		fingerprint("mongo-express-exposed", "mongo-express exposed", SeverityInfo, TargetResponseBody,
			"mongo", `(?i)<title>\s*(?:Mongo Express|mongo-express)`, 0),
		fingerprint("pgadmin-exposed", "pgAdmin exposed", SeverityInfo, TargetResponseBody,
			"pgadmin", `(?i)<title>\s*pgAdmin\b`, 0),
		fingerprint("solr-admin-exposed", "Solr admin exposed", SeverityInfo, TargetResponseBody,
			"solr", `(?i)<title>\s*Solr Admin\b`, 0),
		fingerprint("airflow-exposed", "Airflow exposed", SeverityInfo, TargetResponseBody,
			"", `(?i)(?:<title>\s*(?:Sign In - )?Airflow|/static/appbuilder)`, 0),
		fingerprint("jenkins-exposed", "Jenkins exposed", SeverityInfo, TargetResponseHeader,
			"x-jenkins", `(?im)^x-jenkins:[ \t]*([0-9][0-9.]*)`, 1),
		fingerprint("grafana-exposed", "Grafana exposed", SeverityInfo, TargetResponseBody,
			"grafana", `(?i)window\.grafanaBootData`, 0),
		fingerprint("kibana-exposed", "Kibana exposed", SeverityInfo, TargetResponseHeader,
			"kbn-name", `(?im)^kbn-name:[ \t]*([^\r\n]+)`, 1),
		fingerprint("sonarqube-exposed", "SonarQube exposed", SeverityInfo, TargetResponseBody,
			"sonarqube", `(?i)<title>\s*SonarQube\b`, 0),
		fingerprint("gitlab-exposed", "GitLab exposed", SeverityInfo, TargetResponseBody,
			"gitlab", `(?i)(?:gon\.gitlab_url|<title>\s*GitLab\b)`, 0),
		fingerprint("wordpress-login", "WordPress login exposed", SeverityInfo, TargetResponseBody,
			"login", `(?i)(?:/wp-login\.php|id="loginform")`, 0),
		fingerprint("joomla-admin", "Joomla administrator exposed", SeverityInfo, TargetResponseBody,
			"", `(?i)(?:/administrator/index\.php|Joomla! - Open Source Content Management)`, 0),
		fingerprint("magento-admin", "Magento admin exposed", SeverityInfo, TargetResponseBody,
			"", `(?i)(?:<title>Magento Admin|/admin/admin/dashboard)`, 0),
	}
}

// disclosureRules cover error pages, version fingerprints, internal network
// details, and files that should not be served.
func disclosureRules() []Rule {
	stack := func(id, name string, sev Severity, literal, pattern string, group int) Rule {
		return Rule{
			ID: id, Name: name, Category: CategoryDisclosure, Severity: sev,
			Target: TargetResponseBody, Literal: literal, Pattern: pattern,
			CaptureGroup: group, GroupBy: GroupByURL,
		}
	}
	sqlErr := func(id, name, literal, pattern string) Rule {
		return Rule{
			ID: id, Name: name,
			Description: "A database error message reached the client, which both discloses schema details and indicates unsanitized input reaching the query.",
			// Above Info: a database error reaching the client signals that
			// unsanitised input reaches a query.
			Category: CategoryDisclosure, Severity: SeverityMedium,
			Target: TargetResponseBody, Literal: literal, Pattern: pattern,
			GroupBy: GroupByURL,
		}
	}
	urlFile := func(id, name string, sev Severity, conf Confidence, pattern string, filters ...string) Rule {
		return Rule{
			ID: id, Name: name, Category: CategoryDisclosure, Severity: sev, Confidence: conf,
			Target: TargetURL, Pattern: pattern,
			GroupBy: GroupByURL, StatusCodes: "200",
			PostFilters: filters,
		}
	}

	rules := []Rule{
		// Stack traces and debug pages.
		stack("java-stack-trace", "Java stack trace", SeverityInfo, "",
			`(?m)^\s*at [a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*){2,}\((?:[A-Za-z0-9_$]+\.java:\d+|Native Method|Unknown Source)\)`, 0),
		stack("java-exception-name", "Java exception class name", SeverityInfo, "",
			`\b((?:java|javax|jakarta|org\.(?:springframework|hibernate|apache))\.[A-Za-z0-9.]+(?:Exception|Error))\b`, 1),
		stack("dotnet-stack-trace", "ASP.NET exception", SeverityInfo, "system.",
			`\b(System\.[A-Za-z.]+Exception)\b`, 1),
		stack("aspnet-yellow-screen", "ASP.NET error page", SeverityInfo, "error",
			`(?i)<title>\s*(?:Runtime Error|Server Error in '[^']{0,120}' Application)`, 0),
		stack("iis-detailed-error", "IIS detailed error page", SeverityInfo, "iis",
			`(?i)<title>\s*IIS \d+\.\d+ Detailed Error`, 0),
		stack("python-traceback", "Python traceback", SeverityInfo, "traceback",
			`Traceback \(most recent call last\):[\s\S]{0,400}?(?m)^\s+File "([^"]{1,200})", line \d+`, 1),
		stack("django-debug-page", "Django debug page", SeverityInfo, "",
			`(?i)(?:You're seeing this error because you have <code>DEBUG=True|Django Version:\s*<)`, 0),
		stack("flask-werkzeug-debugger", "Werkzeug interactive debugger", SeverityCritical, "",
			`(?i)(?:Werkzeug Debugger|The debugger caught an exception|console\.js\?__debugger__)`, 0),
		stack("rails-error-page", "Rails error page", SeverityInfo, "",
			`(?i)(?:<title>\s*Action Controller: Exception caught|ActiveRecord::[A-Za-z]+)`, 0),
		stack("rails-web-console", "Rails web console exposed", SeverityCritical, "web-console",
			`(?i)web-console[\s\S]{0,200}(?:REPL|Rails\.env)`, 0),
		stack("php-error-with-path", "PHP error with filesystem path", SeverityInfo, "on line",
			`(?i)\b(?:Fatal error|Parse error|Warning|Notice|Deprecated)\s*:[\s\S]{0,200}?\bin\s+((?:/|[A-Za-z]:\\)[^\s:<]{3,200})\s+on line \d+`, 1),
		stack("laravel-whoops", "Laravel Whoops error page", SeverityInfo, "",
			`(?i)(?:<title>[^<]{0,80}Whoops|/vendor/laravel/framework/src)`, 0),
		stack("node-stack-trace", "Node.js stack trace", SeverityInfo, "    at ",
			`(?m)^\s{4,}at [^\n]{0,160}\((?:/|[A-Za-z]:\\|node:internal|internal/)[^\n]{1,200}:\d+:\d+\)`, 0),
		stack("go-panic", "Go panic trace", SeverityInfo, "goroutine ",
			`(?m)^panic: [^\n]{1,200}\n[\s\S]{0,200}?^goroutine \d+ \[running\]:`, 0),
		stack("spring-whitelabel-error", "Spring whitelabel error page", SeverityInfo, "whitelabel",
			`(?i)Whitelabel Error Page`, 0),
		stack("graphql-verbose-error", "GraphQL error with stack trace", SeverityInfo, "errors",
			`"errors"\s*:\s*\[[\s\S]{0,400}?"(?:stacktrace|exception)"\s*:`, 0),
		{
			ID: "symfony-debug-token", Name: "Symfony profiler token exposed",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "x-debug-token",
			Pattern:      `(?im)^x-debug-token(?:-link)?:[ \t]*([^\r\n]+)`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},

		// SQL errors, one rule per engine so the finding names the DBMS.
		sqlErr("sql-error-mysql", "MySQL error disclosed", "",
			`(?i)(?:You have an error in your SQL syntax|Warning: mysqli?_[a-z_]+\(\)|MySQLSyntaxErrorException|com\.mysql\.(?:jdbc|cj)|check the manual that corresponds to your (?:MySQL|MariaDB))`),
		sqlErr("sql-error-postgres", "PostgreSQL error disclosed", "",
			`(?i)(?:PG::[A-Za-z]+Error|org\.postgresql\.util\.PSQLException|pg_query\(\)|unterminated quoted string at or near|invalid input syntax for)`),
		sqlErr("sql-error-mssql", "SQL Server error disclosed", "",
			`(?i)(?:Unclosed quotation mark after the character string|Incorrect syntax near|System\.Data\.SqlClient\.SqlException|Microsoft OLE DB Provider for SQL Server|\[SQL Server\])`),
		sqlErr("sql-error-oracle", "Oracle error disclosed", "ora-",
			`\b(ORA-\d{5})\b`),
		sqlErr("sql-error-sqlite", "SQLite error disclosed", "",
			`(?i)(?:SQLite3?::[A-Za-z]+|sqlite3\.(?:Operational|Programming)Error|SQLITE_ERROR|unrecognized token:|no such table:)`),
		sqlErr("sql-error-odbc", "ODBC/JET database error disclosed", "",
			`(?i)(?:\[Microsoft\]\[ODBC|Microsoft JET Database Engine|DB2 SQL error|SQLSTATE\[[0-9A-Z]{5}\])`),

		// Version and technology fingerprints.
		{
			ID: "server-header-with-version", Name: "Server header discloses version",
			Description: "Only reported when the header actually contains a version number: a bare 'Server: nginx' is not a finding, and flagging it would drown the real ones.",
			Remediation: "Suppress or genericize the Server header.",
			Category:    CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "server:",
			Pattern:      `(?im)^server:[ \t]*([^\r\n]*[0-9]+\.[0-9]+[^\r\n]*)`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},
		{
			ID: "x-powered-by", Name: "X-Powered-By header present",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "x-powered-by",
			Pattern:      `(?im)^x-powered-by:[ \t]*([^\r\n]+)`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},
		{
			ID: "tech-fingerprint-headers", Name: "Technology fingerprint header",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target:       TargetResponseHeader,
			Pattern:      `(?im)^(x-aspnet-version|x-aspnetmvc-version|x-generator|x-drupal-cache|x-varnish|x-litespeed-cache|x-runtime|x-rack-cache|x-mod-pagespeed|x-shopify-stage|x-turbo-charged-by|liferay-portal):[ \t]*([^\r\n]+)`,
			CaptureGroup: 0, GroupBy: GroupByHost,
		},
		{
			ID: "internal-infra-headers", Name: "Internal infrastructure header",
			Description: "Headers that leak internal hostnames, pool names, or application context.",
			Category:    CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseHeader, Literal: "x-",
			Pattern:      `(?im)^(x-backend-server|x-application-context|x-served-by|x-node|x-real-ip|x-forwarded-server|x-upstream|x-iinfo|x-envoy-upstream-service-time):[ \t]*([^\r\n]+)`,
			CaptureGroup: 0, GroupBy: GroupByHost,
		},
		{
			ID: "generator-meta-tag", Name: "Generator meta tag",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "generator",
			Pattern:      `(?i)<meta\s+name=["']generator["']\s+content=["']([^"']{1,120})["']`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},

		// Internal network and filesystem disclosure.
		{
			ID: "internal-ip-address", Name: "Internal IP address disclosed",
			Description: "A private-range address in a response. The residual false positives are version tuples, which the notVersionString filter suppresses by inspecting neighbouring bytes.",
			Category:    CategoryDisclosure, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b`,
			CaptureGroup: 1, GroupBy: GroupByHost,
			ContentTypes: []string{ctJSON, ctXML, ctPlain, ctHTML},
			PostFilters:  []string{"notVersionString"},
		},
		{
			ID: "cloud-metadata-endpoint", Name: "Cloud metadata endpoint referenced",
			Description: "A link-local metadata address in the response, useful as an SSRF target.",
			Category:    CategoryDisclosure, Severity: SeverityInfo,
			Target:       TargetResponseBody,
			Pattern:      `\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},
		{
			ID: "internal-hostname", Name: "Internal hostname disclosed",
			Category: CategoryDisclosure, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `\b([a-z0-9][a-z0-9-]{1,62}\.(?:local|internal|corp|lan|intranet|localdomain|svc\.cluster\.local|ec2\.internal|compute\.internal))\b`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},
		{
			ID: "absolute-filesystem-path", Name: "Absolute filesystem path disclosed",
			Category: CategoryDisclosure, Severity: SeverityInfo, Confidence: ConfidenceMedium,
			Target:       TargetResponseBody,
			Pattern:      `((?:/(?:home|Users|var/www|var/log|usr/local|opt|srv|root|builds|workspace)/[A-Za-z0-9_.+\-/]{3,140})|(?:[A-Za-z]:\\(?:Users|inetpub|Windows|xampp|wamp|laragon|Sites)\\[A-Za-z0-9 _.+\-\\]{3,140}))`,
			CaptureGroup: 1, GroupBy: GroupByHost,
			ContentTypes: []string{ctJSON, ctXML, ctPlain, ctHTML},
		},
		{
			ID: "source-map-reference", Name: "Source map reference",
			Description: "A sourceMappingURL comment. Verifying the map is actually fetchable is a natural first check for an active scanner.",
			Category:    CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "sourcemappingurl",
			Pattern:      `(?im)^\s*//[#@]\s*sourceMappingURL=([^\r\n]+)`,
			CaptureGroup: 1, GroupBy: GroupByURL,
		},
		{
			ID: "sourcemap-build-path", Name: "Source map discloses build paths",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "sources",
			Pattern:      `"sources"\s*:\s*\[\s*"((?:/|[A-Za-z]:\\|webpack:///)[^"]{4,200})"`,
			CaptureGroup: 1, GroupBy: GroupByURL,
		},
		{
			ID: "aws-account-id-arn", Name: "AWS account ID in ARN",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "arn:aws",
			Pattern:      `\b(arn:aws[a-z-]*:[a-z0-9-]{2,24}:[a-z0-9-]*:\d{12}:)`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},
		{
			ID: "s3-bucket-reference", Name: "S3 bucket reference",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target: TargetResponseBody, Literal: "amazonaws.com",
			Pattern:      `\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]{1,20})?\.amazonaws\.com)\b`,
			CaptureGroup: 1, GroupBy: GroupByHost,
		},

		// Exposed files and listings.
		{
			ID: "directory-listing", Name: "Directory listing enabled",
			Description: "An autoindex page. Requires both the title and a sort-link marker, so a page merely titled 'Index of things' is not reported.",
			Remediation: "Disable directory indexing for the path.",
			Category:    CategoryDisclosure, Severity: SeverityInfo,
			Target:      TargetResponseBody,
			Pattern:     `(?i)(?:<title>\s*Index of /|<h1>\s*Index of /|<title>\s*Directory Listing (?:For|of)|To Parent Directory</a>)`,
			GroupBy:     GroupByURL,
			StatusCodes: "200",
		},
		{
			ID: "phpinfo-page", Name: "phpinfo() page exposed",
			Category: CategoryDisclosure, Severity: SeverityInfo,
			Target:      TargetResponseBody,
			Pattern:     `(?i)(?:<title>\s*phpinfo\(\)|>phpinfo\(\)</h1>|<h1 class="p">PHP Version)`,
			GroupBy:     GroupByURL,
			StatusCodes: "200",
		},
		urlFile("config-file-exposed", "Configuration file exposed", SeverityLow, ConfidenceHigh,
			`(?i)/(?:\.env(?:\.[a-z0-9]+)?|web\.config|app\.config|appsettings(?:\.[A-Za-z]+)?\.json|settings\.py|local_settings\.py|application\.(?:ya?ml|properties)|database\.ya?ml|secrets\.ya?ml|docker-compose(?:\.[a-z]+)?\.ya?ml|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.htpasswd|credentials\.json|id_(?:rsa|dsa|ecdsa|ed25519))$`,
			"notHTML"),
		urlFile("backup-or-temp-file", "Backup or temporary file exposed", SeverityLow, ConfidenceMedium,
			`(?i)\.(?:bak|old|orig|save|sav|swp|swo|tmp|backup|copy|dist|inc)$|(?i)\.(?:php|asp|aspx|jsp|rb|py|js|json|ya?ml|xml|conf|ini)\.(?:bak|old|txt|save|orig|dist|sample)$`,
			"notHTML"),
		urlFile("archive-or-dump-exposed", "Archive or database dump exposed", SeverityCritical, ConfidenceMedium,
			`(?i)\.(?:sql|sql\.gz|dump|dmp|bacpac|mdb|sqlite3?|war|jar|ear|pst|vmdk|ova)$`,
			"notHTML"),
		urlFile("vcs-metadata-exposed", "Version control metadata exposed", SeverityHigh, ConfidenceHigh,
			`(?i)/\.(?:git/(?:HEAD|config|index|packed-refs)|svn/(?:entries|wc\.db)|hg/(?:requires|hgrc)|bzr/branch-format)$`,
			"notHTML"),
		urlFile("ide-editor-artifacts", "IDE or editor artifact exposed", SeverityLow, ConfidenceHigh,
			`(?i)/(?:\.vscode/|\.idea/|\.project$|\.settings/|nbproject/|\.sublime-project$)`,
			"notHTML"),
		urlFile("ci-config-exposed", "CI configuration exposed", SeverityLow, ConfidenceHigh,
			`(?i)/(?:\.gitlab-ci\.ya?ml|\.travis\.ya?ml|\.circleci/config\.ya?ml|Jenkinsfile|azure-pipelines\.ya?ml|buildspec\.ya?ml)$`,
			"notHTML"),
		urlFile("ds-store-exposed", "macOS .DS_Store exposed", SeverityLow, ConfidenceHigh,
			`(?i)/\.DS_Store$`, "notHTML"),
		{
			ID: "dependency-manifest-exposed", Name: "Dependency manifest exposed",
			Description: "A dependency manifest served to clients. Normal for npm packages and many static deploys, so this is not itself a weakness — the value is the exact dependency versions it hands over for CVE cross-referencing.",
			Category:    CategoryDisclosure, Severity: SeverityLow,
			Target:  TargetURL,
			Pattern: `(?i)/(?:composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock|Gemfile(?:\.lock)?|requirements\.txt|Pipfile(?:\.lock)?|go\.(?:mod|sum)|pom\.xml)$`,
			GroupBy: GroupByURL, StatusCodes: "200",
		},
	}
	return rules
}
