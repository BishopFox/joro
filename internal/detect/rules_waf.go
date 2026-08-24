package detect

// This file is generated from the nuclei "Global WAF Detect Matchers" template
// and ported to the detect engine's rule model. Each rule is a KindRegex rule at
// Info severity, Low confidence, grouped per host, in the Disclosure category: a
// WAF's presence is an infrastructure disclosure, not an exploitable weakness.
//
// Porting decisions:
//   - The engine matches one message part per rule (TargetMessage is rejected at
//     rebuild), while nuclei's part: response means headers+body. A part:
//     response WAF is therefore emitted as TWO rules sharing the same pattern:
//     one over the response body (block-page text) and one over the response
//     headers (Server/Set-Cookie fingerprints, which show on ordinary 200s too).
//     part: header WAFs and the header/cookie-only ones get the header rule only;
//     part: body WAFs get the body rule only. The header variant's ID is
//     suffixed -hdr and its name "(headers)".
//   - nuclei condition: and cannot be one RE2 alternation, so those WAFs use
//     their single most distinctive branch.
//   - type: word matchers are escaped into a case-insensitive alternation.
//   - GroupByHost collapses each WAF to one finding per host in the store.
//   - Precision trims vs upstream: alertlogic, apachegeneric, and aspgeneric were
//     dropped entirely (all-generic server/404 text), and the generic branches of
//     yundun, barikode, securesphere, safedog, and modsecurityowasp were removed;
//     exact WAF block-page wordings (fortigate, akamai) are kept.
//
// Performance: each rule carries an any-of Literals prescreen (the third waf()
// argument) - a set of lowercase anchor substrings, one guaranteed-present run
// from every alternation branch. On traffic that is not behind the WAF none of
// the anchors appear, so the engine skips the regex after a cheap bytes.Contains
// instead of scanning the whole (up to 1 MB) body. Fourteen rules whose branches
// anchor only on a 2-3 char cookie/token prefix (cloudflare, aws, cloudfront,
// teros, wts, west263, bigip, airlock) pass nil and run unscreened, as before -
// no anchor selective enough to help. Anchors must stay in sync with the pattern:
// a wrong anchor silently drops matches from the branch it was meant to cover.
//
// Every pattern compiles under RE2 and is exercised by the Go build.

// wafRules returns the WAF fingerprint rules. Called from builtinRules.
func wafRules() []Rule {
	waf := func(id, name, pattern string, target Target, literals []string) Rule {
		return Rule{
			ID: id, Name: name,
			Description: "Response carries a fingerprint of the " + name +
				" web application firewall (passive signature ported from the nuclei global WAF matchers).",
			Category: CategoryDisclosure, Severity: SeverityInfo, Confidence: ConfidenceLow,
			Target: target, GroupBy: GroupByHost,
			Pattern: pattern, Literals: literals,
		}
	}
	return []Rule{
		waf(`waf-instart`, `Instart WAF detected`, `(?i)instartrequestid`, TargetResponseBody, []string{"instartrequestid"}),
		waf(`waf-perimx`, `Perimx WAF detected`, `(?i)access.to.this.page.has.been.denied.because.we.believe.you.are.using.automation.tool|(?i)http(s)?://(www.)?perimeterx.\w+.whywasiblocked|(?i)perimeterx|(?i)(..)?client.perimeterx.*/[a-zA-Z]{8,15}/*.*.js`, TargetResponseBody, []string{"automation", "whywasiblocked", "perimeterx"}),
		waf(`waf-perimx-hdr`, `Perimx WAF detected (headers)`, `(?i)access.to.this.page.has.been.denied.because.we.believe.you.are.using.automation.tool|(?i)http(s)?://(www.)?perimeterx.\w+.whywasiblocked|(?i)perimeterx|(?i)(..)?client.perimeterx.*/[a-zA-Z]{8,15}/*.*.js`, TargetResponseHeader, []string{"automation", "whywasiblocked", "perimeterx"}),
		waf(`waf-webknight`, `Webknight WAF detected`, `(?i)\bwebknight|(?i)webknight`, TargetResponseBody, []string{"webknight"}),
		waf(`waf-webknight-hdr`, `Webknight WAF detected (headers)`, `(?i)\bwebknight|(?i)webknight`, TargetResponseHeader, []string{"webknight"}),
		waf(`waf-zscaler`, `Zscaler WAF detected`, `(?i)zscaler(.\d+(.\d+)?)?|(?i)zscaler`, TargetResponseBody, []string{"zscaler"}),
		waf(`waf-zscaler-hdr`, `Zscaler WAF detected (headers)`, `(?i)zscaler(.\d+(.\d+)?)?|(?i)zscaler`, TargetResponseHeader, []string{"zscaler"}),
		waf(`waf-fortigate`, `Fortigate WAF detected`, `(?i).>powered.by.fortinet<.|(?i).>fortigate.ips.sensor<.|(?i)fortigate|(?i).fgd_icon|(?i)\AFORTIWAFSID=|(?i)application.blocked.|(?i).fortiGate.application.control|(?i)(http(s)?)?://\w+.fortinet(.\w+:)?|(?i)fortigate.hostname|(?i)the.page.cannot.be.displayed..please.contact.[^@]+@[^@]+\.[^@]+.for.additional.information`, TargetResponseBody, []string{"fortinet", "fortigate", "fgd_icon", "fortiwafsid", "application", "information"}),
		waf(`waf-fortigate-hdr`, `Fortigate WAF detected (headers)`, `(?i).>powered.by.fortinet<.|(?i).>fortigate.ips.sensor<.|(?i)fortigate|(?i).fgd_icon|(?i)\AFORTIWAFSID=|(?i)application.blocked.|(?i).fortiGate.application.control|(?i)(http(s)?)?://\w+.fortinet(.\w+:)?|(?i)fortigate.hostname|(?i)the.page.cannot.be.displayed..please.contact.[^@]+@[^@]+\.[^@]+.for.additional.information`, TargetResponseHeader, []string{"fortinet", "fortigate", "fgd_icon", "fortiwafsid", "application", "information"}),
		waf(`waf-teros`, `Teros WAF detected`, `(?i)st8(id|.wa|.wf)?.?(\d+|\w+)?=`, TargetResponseHeader, nil),
		waf(`waf-stricthttp`, `Stricthttp WAF detected`, `(?i)the.request.was.rejected.because.the.url.contained.a.potentially.malicious.string|(?i)rejected.by.url.scan|(?i)/rejected.by.url.scan`, TargetResponseBody, []string{"potentially", "rejected"}),
		waf(`waf-stricthttp-hdr`, `Stricthttp WAF detected (headers)`, `(?i)the.request.was.rejected.because.the.url.contained.a.potentially.malicious.string|(?i)rejected.by.url.scan|(?i)/rejected.by.url.scan`, TargetResponseHeader, []string{"potentially", "rejected"}),
		waf(`waf-shadowd`, `Shadowd WAF detected`, `(?i)request.forbidden.by.administrative.rules.`, TargetResponseBody, []string{"administrative"}),
		waf(`waf-shadowd-hdr`, `Shadowd WAF detected (headers)`, `(?i)request.forbidden.by.administrative.rules.`, TargetResponseHeader, []string{"administrative"}),
		waf(`waf-bigip`, `Bigip WAF detected`, `(?i)\ATS\w{4,}=|(?i)bigipserver(.i)?|bigipserverinternal|(?i)^TS[a-zA-Z0-9]{3,8}=|(?i)BigIP|BIG-IP|BIGIP|(?i)bigipserver`, TargetResponseBody, nil),
		waf(`waf-bigip-hdr`, `Bigip WAF detected (headers)`, `(?i)\ATS\w{4,}=|(?i)bigipserver(.i)?|bigipserverinternal|(?i)^TS[a-zA-Z0-9]{3,8}=|(?i)BigIP|BIG-IP|BIGIP|(?i)bigipserver`, TargetResponseHeader, nil),
		waf(`waf-edgecast`, `Edgecast WAF detected`, `(?i)\Aecdf`, TargetResponseHeader, []string{"ecdf"}),
		waf(`waf-radware`, `Radware WAF detected`, `(?i).\bcloudwebsec.radware.com\b.|(?i).>unauthorized.activity.has.been.detected<.|(?i)with.the.following.case.number.in.its.subject:.\d+.`, TargetResponseBody, []string{"cloudwebsec", "unauthorized", "following"}),
		waf(`waf-radware-hdr`, `Radware WAF detected (headers)`, `(?i).\bcloudwebsec.radware.com\b.|(?i).>unauthorized.activity.has.been.detected<.|(?i)with.the.following.case.number.in.its.subject:.\d+.`, TargetResponseHeader, []string{"cloudwebsec", "unauthorized", "following"}),
		waf(`waf-varnish`, `Varnish WAF detected`, `(?i)varnish|(?i).>.?security.by.cachewall.?<.|(?i)cachewall|(?i).>access.is.blocked.according.to.our.site.security.policy.<+`, TargetResponseBody, []string{"varnish", "cachewall", "according"}),
		waf(`waf-varnish-hdr`, `Varnish WAF detected (headers)`, `(?i)varnish|(?i).>.?security.by.cachewall.?<.|(?i)cachewall|(?i).>access.is.blocked.according.to.our.site.security.policy.<+`, TargetResponseHeader, []string{"varnish", "cachewall", "according"}),
		waf(`waf-infosafe`, `Infosafe WAF detected`, `(?i)infosafe|(?i)by.(http(s)?(.//)?)?7i24.(com|net)|(?i)infosafe.\d.\d|(?i)var.infosafekey=`, TargetResponseBody, []string{"infosafe", "7i24", "infosafekey"}),
		waf(`waf-infosafe-hdr`, `Infosafe WAF detected (headers)`, `(?i)infosafe|(?i)by.(http(s)?(.//)?)?7i24.(com|net)|(?i)infosafe.\d.\d|(?i)var.infosafekey=`, TargetResponseHeader, []string{"infosafe", "7i24", "infosafekey"}),
		waf(`waf-aliyundun`, `Aliyundun WAF detected`, `(?i)error(s)?.aliyun(dun)?.(com|net)|(?i)http(s)?://(www.)?aliyun.(com|net)`, TargetResponseBody, []string{"aliyun"}),
		waf(`waf-aliyundun-hdr`, `Aliyundun WAF detected (headers)`, `(?i)error(s)?.aliyun(dun)?.(com|net)|(?i)http(s)?://(www.)?aliyun.(com|net)`, TargetResponseHeader, []string{"aliyun"}),
		waf(`waf-malcare`, `Malcare WAF detected`, `(?i)malcare|(?i).>login.protection<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?|(?i).>firewall<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?`, TargetResponseBody, []string{"malcare", "protection", "firewall"}),
		waf(`waf-malcare-hdr`, `Malcare WAF detected (headers)`, `(?i)malcare|(?i).>login.protection<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?|(?i).>firewall<.+.><.+>powered.by<.+.>(<.+.>)?(.?malcare.-.pro|blogvault)?`, TargetResponseHeader, []string{"malcare", "protection", "firewall"}),
		waf(`waf-wts`, `Wts WAF detected`, `(?i)(<title>)?wts.wa(f)?(\w+(\w+(\w+)?)?)?`, TargetResponseBody, nil),
		waf(`waf-wts-hdr`, `Wts WAF detected (headers)`, `(?i)(<title>)?wts.wa(f)?(\w+(\w+(\w+)?)?)?`, TargetResponseHeader, nil),
		waf(`waf-dw`, `Dw WAF detected`, `(?i)dw.inj.check`, TargetResponseBody, []string{"check"}),
		waf(`waf-dw-hdr`, `Dw WAF detected (headers)`, `(?i)dw.inj.check`, TargetResponseHeader, []string{"check"}),
		waf(`waf-denyall`, `Denyall WAF detected`, `(?i)\Acondition.intercepted|(?i)\Asessioncookie=`, TargetResponseHeader, []string{"intercepted", "sessioncookie"}),
		waf(`waf-yunsuo`, `Yunsuo WAF detected`, `(?i)<img.class=.yunsuologo.|(?i)yunsuo.session|(?i)yunsuologo`, TargetResponseBody, []string{"yunsuologo", "session"}),
		waf(`waf-yunsuo-hdr`, `Yunsuo WAF detected (headers)`, `(?i)<img.class=.yunsuologo.|(?i)yunsuo.session|(?i)yunsuologo`, TargetResponseHeader, []string{"yunsuologo", "session"}),
		waf(`waf-litespeed`, `Litespeed WAF detected`, `(?i)litespeed.web.server`, TargetResponseBody, []string{"litespeed"}),
		waf(`waf-litespeed-hdr`, `Litespeed WAF detected (headers)`, `(?i)litespeed.web.server`, TargetResponseHeader, []string{"litespeed"}),
		waf(`waf-cloudfront`, `Cloudfront WAF detected`, `(?i)[a-zA-Z0-9]{,60}.cloudfront.net|(?i)cloudfront|(?i)x.amz.cf.id|nguardx`, TargetResponseBody, nil),
		waf(`waf-cloudfront-hdr`, `Cloudfront WAF detected (headers)`, `(?i)[a-zA-Z0-9]{,60}.cloudfront.net|(?i)cloudfront|(?i)x.amz.cf.id|nguardx`, TargetResponseHeader, nil),
		waf(`waf-anyu`, `Anyu WAF detected`, `(?i)sorry.{1,2}your.access.has.been.intercept(ed)?.by.anyu|(?i)anyu|(?i)anyu-?.the.green.channel`, TargetResponseBody, []string{"intercept", "anyu", "channel"}),
		waf(`waf-anyu-hdr`, `Anyu WAF detected (headers)`, `(?i)sorry.{1,2}your.access.has.been.intercept(ed)?.by.anyu|(?i)anyu|(?i)anyu-?.the.green.channel`, TargetResponseHeader, []string{"intercept", "anyu", "channel"}),
		waf(`waf-googlewebservices`, `Googlewebservices WAF detected`, `(?i)your.client.has.issued.a.malformed.or.illegal.request|(?i)our.systems.have.detected.unusual.traffic|(?i)block(ed)?.by.g.cloud.security.policy.+`, TargetResponseBody, []string{"malformed", "detected", "security"}),
		waf(`waf-googlewebservices-hdr`, `Googlewebservices WAF detected (headers)`, `(?i)your.client.has.issued.a.malformed.or.illegal.request|(?i)our.systems.have.detected.unusual.traffic|(?i)block(ed)?.by.g.cloud.security.policy.+`, TargetResponseHeader, []string{"malformed", "detected", "security"}),
		waf(`waf-didiyun`, `Didiyun WAF detected`, `(?i)(http(s)?://)(sec-waf.|www.)?didi(static|yun)?.com(/static/cloudwafstatic)?|(?i)didiyun`, TargetResponseBody, []string{"didi", "didiyun"}),
		waf(`waf-didiyun-hdr`, `Didiyun WAF detected (headers)`, `(?i)(http(s)?://)(sec-waf.|www.)?didi(static|yun)?.com(/static/cloudwafstatic)?|(?i)didiyun`, TargetResponseHeader, []string{"didi", "didiyun"}),
		waf(`waf-blockdos`, `Blockdos WAF detected`, `(?i)blockdos\.net`, TargetResponseBody, []string{"blockdos"}),
		waf(`waf-blockdos-hdr`, `Blockdos WAF detected (headers)`, `(?i)blockdos\.net`, TargetResponseHeader, []string{"blockdos"}),
		waf(`waf-codeigniter`, `Codeigniter WAF detected`, `(?i)the.uri.you.submitted.has.disallowed.characters`, TargetResponseBody, []string{"disallowed"}),
		waf(`waf-codeigniter-hdr`, `Codeigniter WAF detected (headers)`, `(?i)the.uri.you.submitted.has.disallowed.characters`, TargetResponseHeader, []string{"disallowed"}),
		waf(`waf-stingray`, `Stingray WAF detected`, `(?i)\AX-Mapping-`, TargetResponseHeader, []string{"mapping"}),
		waf(`waf-west263`, `West263 WAF detected`, `(?i)wt\d*cdn`, TargetResponseBody, nil),
		waf(`waf-west263-hdr`, `West263 WAF detected (headers)`, `(?i)wt\d*cdn`, TargetResponseHeader, nil),
		waf(`waf-aws`, `Aws WAF detected`, `(?i)<RequestId>[0-9a-zA-Z]{16,25}<.RequestId>|(?i)<Error><Code>AccessDenied<.Code>|(?i)x.amz.id.\d+|(?i)x.amz.request.id`, TargetResponseBody, nil),
		waf(`waf-aws-hdr`, `Aws WAF detected (headers)`, `(?i)<RequestId>[0-9a-zA-Z]{16,25}<.RequestId>|(?i)<Error><Code>AccessDenied<.Code>|(?i)x.amz.id.\d+|(?i)x.amz.request.id`, TargetResponseHeader, nil),
		waf(`waf-yundun`, `Yundun WAF detected`, `(?i)YUNDUN|(?i)^yd.cookie=|(?i)http(s)?.//(www\.)?(\w+.)?yundun(.com)?`, TargetResponseBody, []string{"yundun", "cookie"}),
		waf(`waf-yundun-hdr`, `Yundun WAF detected (headers)`, `(?i)YUNDUN|(?i)^yd.cookie=|(?i)http(s)?.//(www\.)?(\w+.)?yundun(.com)?`, TargetResponseHeader, []string{"yundun", "cookie"}),
		waf(`waf-barracuda`, `Barracuda WAF detected`, `(?i)\Abarra.counter.session=?|(?i)(\A|\b)?barracuda.|(?i)barracuda.networks.{1,2}inc`, TargetResponseBody, []string{"counter", "barracuda"}),
		waf(`waf-barracuda-hdr`, `Barracuda WAF detected (headers)`, `(?i)\Abarra.counter.session=?|(?i)(\A|\b)?barracuda.|(?i)barracuda.networks.{1,2}inc`, TargetResponseHeader, []string{"counter", "barracuda"}),
		waf(`waf-dodenterpriseprotection`, `Dodenterpriseprotection WAF detected`, `(?i)dod.enterprise.level.protection.system`, TargetResponseBody, []string{"enterprise"}),
		waf(`waf-dodenterpriseprotection-hdr`, `Dodenterpriseprotection WAF detected (headers)`, `(?i)dod.enterprise.level.protection.system`, TargetResponseHeader, []string{"enterprise"}),
		waf(`waf-secupress`, `Secupress WAF detected`, `(?i)<h\d*>secupress<.|(?i)block.id.{1,2}bad.url.contents.<.`, TargetResponseBody, []string{"secupress", "contents"}),
		waf(`waf-secupress-hdr`, `Secupress WAF detected (headers)`, `(?i)<h\d*>secupress<.|(?i)block.id.{1,2}bad.url.contents.<.`, TargetResponseHeader, []string{"secupress", "contents"}),
		waf(`waf-aesecure`, `Aesecure WAF detected`, `(?i)aesecure.denied.png`, TargetResponseBody, []string{"aesecure"}),
		waf(`waf-aesecure-hdr`, `Aesecure WAF detected (headers)`, `(?i)aesecure.denied.png`, TargetResponseHeader, []string{"aesecure"}),
		waf(`waf-incapsula`, `Incapsula WAF detected`, `(?i)incap_ses|visid_incap|(?i)incapsula|(?i)incapsula.incident.id`, TargetResponseBody, []string{"incap_ses", "visid_incap", "incapsula"}),
		waf(`waf-incapsula-hdr`, `Incapsula WAF detected (headers)`, `(?i)incap_ses|visid_incap|(?i)incapsula|(?i)incapsula.incident.id`, TargetResponseHeader, []string{"incap_ses", "visid_incap", "incapsula"}),
		waf(`waf-nexusguard`, `Nexusguard WAF detected`, `(?i)nexus.?guard|(?i)((http(s)?://)?speresources.)?nexusguard.com.wafpage`, TargetResponseBody, []string{"nexus", "nexusguard"}),
		waf(`waf-nexusguard-hdr`, `Nexusguard WAF detected (headers)`, `(?i)nexus.?guard|(?i)((http(s)?://)?speresources.)?nexusguard.com.wafpage`, TargetResponseHeader, []string{"nexus", "nexusguard"}),
		waf(`waf-cloudflare`, `Cloudflare WAF detected`, `(?i)cloudflare.ray.id.|var.cloudflare.|(?i)cloudflare.nginx|(?i)..cfduid=([a-z0-9]{43})?|(?i)cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?|(?i).>attention.required!.\|.cloudflare<.+|(?i)http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?|(?i)ray.id|(?i)__cfduid`, TargetResponseBody, nil),
		waf(`waf-cloudflare-hdr`, `Cloudflare WAF detected (headers)`, `(?i)cloudflare.ray.id.|var.cloudflare.|(?i)cloudflare.nginx|(?i)..cfduid=([a-z0-9]{43})?|(?i)cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?|(?i).>attention.required!.\|.cloudflare<.+|(?i)http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?|(?i)ray.id|(?i)__cfduid`, TargetResponseHeader, nil),
		waf(`waf-akamai`, `Akamai WAF detected`, `(?i).>access.denied<.|(?i)akamaighost|(?i)ak.bmsc.`, TargetResponseBody, []string{"access", "akamaighost", "bmsc"}),
		waf(`waf-akamai-hdr`, `Akamai WAF detected (headers)`, `(?i).>access.denied<.|(?i)akamaighost|(?i)ak.bmsc.`, TargetResponseHeader, []string{"access", "akamaighost", "bmsc"}),
		waf(`waf-webseal`, `Webseal WAF detected`, `(?i)webseal.error.message.template|(?i)webseal.server.received.an.invalid.http.request`, TargetResponseBody, []string{"template", "received"}),
		waf(`waf-webseal-hdr`, `Webseal WAF detected (headers)`, `(?i)webseal.error.message.template|(?i)webseal.server.received.an.invalid.http.request`, TargetResponseHeader, []string{"template", "received"}),
		waf(`waf-dotdefender`, `Dotdefender WAF detected`, `(?i)dotdefender.blocked.your.request`, TargetResponseBody, []string{"dotdefender"}),
		waf(`waf-dotdefender-hdr`, `Dotdefender WAF detected (headers)`, `(?i)dotdefender.blocked.your.request`, TargetResponseHeader, []string{"dotdefender"}),
		waf(`waf-pk`, `Pk WAF detected`, `(?i).>pkSecurityModule\W..\WSecurity.Alert<.|(?i).http(s)?.//([w]{3})?.kitnetwork.\w|(?i).>A.safety.critical.request.was.discovered.and.blocked.<.`, TargetResponseBody, []string{"pksecuritymodule", "kitnetwork", "discovered"}),
		waf(`waf-pk-hdr`, `Pk WAF detected (headers)`, `(?i).>pkSecurityModule\W..\WSecurity.Alert<.|(?i).http(s)?.//([w]{3})?.kitnetwork.\w|(?i).>A.safety.critical.request.was.discovered.and.blocked.<.`, TargetResponseHeader, []string{"pksecuritymodule", "kitnetwork", "discovered"}),
		waf(`waf-expressionengine`, `Expressionengine WAF detected`, `(?i).>error.-.expressionengine<.|(?i).>:.the.uri.you.submitted.has.disallowed.characters.<.|(?i)invalid.(get|post).data`, TargetResponseBody, []string{"expressionengine", "disallowed", "invalid"}),
		waf(`waf-expressionengine-hdr`, `Expressionengine WAF detected (headers)`, `(?i).>error.-.expressionengine<.|(?i).>:.the.uri.you.submitted.has.disallowed.characters.<.|(?i)invalid.(get|post).data`, TargetResponseHeader, []string{"expressionengine", "disallowed", "invalid"}),
		waf(`waf-comodo`, `Comodo WAF detected`, `(?i)protected.by.comodo.waf`, TargetResponseBody, []string{"protected"}),
		waf(`waf-comodo-hdr`, `Comodo WAF detected (headers)`, `(?i)protected.by.comodo.waf`, TargetResponseHeader, []string{"protected"}),
		waf(`waf-ciscoacexml`, `Ciscoacexml WAF detected`, `(?i)ace.xml.gateway`, TargetResponseBody, []string{"gateway"}),
		waf(`waf-ciscoacexml-hdr`, `Ciscoacexml WAF detected (headers)`, `(?i)ace.xml.gateway`, TargetResponseHeader, []string{"gateway"}),
		waf(`waf-barikode`, `Barikode WAF detected`, `(?i).>barikode<.`, TargetResponseBody, []string{"barikode"}),
		waf(`waf-barikode-hdr`, `Barikode WAF detected (headers)`, `(?i).>barikode<.`, TargetResponseHeader, []string{"barikode"}),
		waf(`waf-watchguard`, `Watchguard WAF detected`, `(?i)(request.denied.by.)?watchguard.firewall|(?i)watchguard(.technologies(.inc)?)?`, TargetResponseBody, []string{"watchguard"}),
		waf(`waf-watchguard-hdr`, `Watchguard WAF detected (headers)`, `(?i)(request.denied.by.)?watchguard.firewall|(?i)watchguard(.technologies(.inc)?)?`, TargetResponseHeader, []string{"watchguard"}),
		waf(`waf-binarysec`, `Binarysec WAF detected`, `(?i)x.binarysec.via|(?i)x.binarysec.nocache|(?i)binarysec`, TargetResponseBody, []string{"binarysec"}),
		waf(`waf-binarysec-hdr`, `Binarysec WAF detected (headers)`, `(?i)x.binarysec.via|(?i)x.binarysec.nocache|(?i)binarysec`, TargetResponseHeader, []string{"binarysec"}),
		waf(`waf-bekchy`, `Bekchy WAF detected`, `(?i)bekchy.(-.)?access.denied|(?i)(http(s)?://)(www.)?bekchy.com(/report)?`, TargetResponseBody, []string{"bekchy"}),
		waf(`waf-bekchy-hdr`, `Bekchy WAF detected (headers)`, `(?i)bekchy.(-.)?access.denied|(?i)(http(s)?://)(www.)?bekchy.com(/report)?`, TargetResponseHeader, []string{"bekchy"}),
		waf(`waf-bitninja`, `Bitninja WAF detected`, `(?i)bitninja|(?i)security.check.by.bitninja|(?i).>visitor.anti(\S)?robot.validation<.`, TargetResponseBody, []string{"bitninja", "security", "validation"}),
		waf(`waf-bitninja-hdr`, `Bitninja WAF detected (headers)`, `(?i)bitninja|(?i)security.check.by.bitninja|(?i).>visitor.anti(\S)?robot.validation<.`, TargetResponseHeader, []string{"bitninja", "security", "validation"}),
		waf(`waf-greywizard`, `Greywizard WAF detected`, `(?i)greywizard(.\d.\d(.\d)?)?|(?i)grey.wizard.block|(?i)(http(s)?.//)?(\w+.)?greywizard.com|(?i)grey.wizard`, TargetResponseBody, []string{"greywizard", "wizard"}),
		waf(`waf-greywizard-hdr`, `Greywizard WAF detected (headers)`, `(?i)greywizard(.\d.\d(.\d)?)?|(?i)grey.wizard.block|(?i)(http(s)?.//)?(\w+.)?greywizard.com|(?i)grey.wizard`, TargetResponseHeader, []string{"greywizard", "wizard"}),
		waf(`waf-configserver`, `Configserver WAF detected`, `(?i).>the.firewall.on.this.server.is.blocking.your.connection.<+`, TargetResponseBody, []string{"connection"}),
		waf(`waf-configserver-hdr`, `Configserver WAF detected (headers)`, `(?i).>the.firewall.on.this.server.is.blocking.your.connection.<+`, TargetResponseHeader, []string{"connection"}),
		waf(`waf-viettel`, `Viettel WAF detected`, `(?i)<title>access.denied(...)?viettel.waf</title>|(?i)viettel.waf.system|(?i)(http(s).//)?cloudrity.com(.vn)?`, TargetResponseBody, []string{"viettel", "cloudrity"}),
		waf(`waf-viettel-hdr`, `Viettel WAF detected (headers)`, `(?i)<title>access.denied(...)?viettel.waf</title>|(?i)viettel.waf.system|(?i)(http(s).//)?cloudrity.com(.vn)?`, TargetResponseHeader, []string{"viettel", "cloudrity"}),
		waf(`waf-safedog`, `Safedog WAF detected`, `(?i)(http(s)?)?(://)?(www|404|bbs|\w+)?.safedog.\w|(?i)X\-Safe\-Firewall|safedog\-flow`, TargetResponseHeader, []string{"safedog", "firewall"}),
		waf(`waf-baidu`, `Baidu WAF detected`, `(?i)yunjiasu.nginx`, TargetResponseBody, []string{"yunjiasu"}),
		waf(`waf-baidu-hdr`, `Baidu WAF detected (headers)`, `(?i)yunjiasu.nginx`, TargetResponseHeader, []string{"yunjiasu"}),
		waf(`waf-armor`, `Armor WAF detected`, `(?i)blocked.by.website.protection.from.armour`, TargetResponseBody, []string{"protection"}),
		waf(`waf-armor-hdr`, `Armor WAF detected (headers)`, `(?i)blocked.by.website.protection.from.armour`, TargetResponseHeader, []string{"protection"}),
		waf(`waf-dosarrest`, `Dosarrest WAF detected`, `(?i)dosarrest|(?i)x.dis.request.id`, TargetResponseBody, []string{"dosarrest", "request"}),
		waf(`waf-dosarrest-hdr`, `Dosarrest WAF detected (headers)`, `(?i)dosarrest|(?i)x.dis.request.id`, TargetResponseHeader, []string{"dosarrest", "request"}),
		waf(`waf-paloalto`, `Paloalto WAF detected`, `has.been.blocked.in.accordance.with.company.policy|.>Virus.Spyware.Download.Blocked<.`, TargetResponseBody, []string{"accordance", "download"}),
		waf(`waf-paloalto-hdr`, `Paloalto WAF detected (headers)`, `has.been.blocked.in.accordance.with.company.policy|.>Virus.Spyware.Download.Blocked<.`, TargetResponseHeader, []string{"accordance", "download"}),
		waf(`waf-powerful`, `Powerful WAF detected`, `(?i)Powerful Firewall|(?i)http(s)?...tiny.cc.powerful.firewall`, TargetResponseBody, []string{"powerful"}),
		waf(`waf-powerful-hdr`, `Powerful WAF detected (headers)`, `(?i)Powerful Firewall|(?i)http(s)?...tiny.cc.powerful.firewall`, TargetResponseHeader, []string{"powerful"}),
		waf(`waf-uewaf`, `Uewaf WAF detected`, `(?i)http(s)?.//ucloud|(?i)uewaf(.deny.pages)`, TargetResponseBody, []string{"ucloud", "uewaf"}),
		waf(`waf-uewaf-hdr`, `Uewaf WAF detected (headers)`, `(?i)http(s)?.//ucloud|(?i)uewaf(.deny.pages)`, TargetResponseHeader, []string{"ucloud", "uewaf"}),
		waf(`waf-janusec`, `Janusec WAF detected`, `(?i)janusec|(?i)(http(s)?\W+(www.)?)?janusec.(com|net|org)`, TargetResponseBody, []string{"janusec"}),
		waf(`waf-janusec-hdr`, `Janusec WAF detected (headers)`, `(?i)janusec|(?i)(http(s)?\W+(www.)?)?janusec.(com|net|org)`, TargetResponseHeader, []string{"janusec"}),
		waf(`waf-siteguard`, `Siteguard WAF detected`, `(?i)>Powered.by.SiteGuard.Lite<|(?i)refuse.to.browse`, TargetResponseBody, []string{"siteguard", "refuse"}),
		waf(`waf-siteguard-hdr`, `Siteguard WAF detected (headers)`, `(?i)>Powered.by.SiteGuard.Lite<|(?i)refuse.to.browse`, TargetResponseHeader, []string{"siteguard", "refuse"}),
		waf(`waf-sonicwall`, `Sonicwall WAF detected`, `(?i)This.request.is.blocked.by.the.SonicWALL|(?i)Dell.SonicWALL|(?i)Web.Site.Blocked.+\bnsa.banner|(?i)SonicWALL|(?i).>policy.this.site.is.blocked<.`, TargetResponseBody, []string{"sonicwall", "blocked"}),
		waf(`waf-sonicwall-hdr`, `Sonicwall WAF detected (headers)`, `(?i)This.request.is.blocked.by.the.SonicWALL|(?i)Dell.SonicWALL|(?i)Web.Site.Blocked.+\bnsa.banner|(?i)SonicWALL|(?i).>policy.this.site.is.blocked<.`, TargetResponseHeader, []string{"sonicwall", "blocked"}),
		waf(`waf-jiasule`, `Jiasule WAF detected`, `(?i)^jsl(_)?tracking|(?i)(__)?jsluid(=)?|(?i)notice.jiasule|(?i)(static|www|dynamic).jiasule.(com|net)`, TargetResponseBody, []string{"tracking", "jsluid", "jiasule"}),
		waf(`waf-jiasule-hdr`, `Jiasule WAF detected (headers)`, `(?i)^jsl(_)?tracking|(?i)(__)?jsluid(=)?|(?i)notice.jiasule|(?i)(static|www|dynamic).jiasule.(com|net)`, TargetResponseHeader, []string{"tracking", "jsluid", "jiasule"}),
		waf(`waf-nginxgeneric`, `Nginxgeneric WAF detected`, `(?i)nginx|(?i)you.do(not|n.t)?.have.permission.to.access.this.document`, TargetResponseBody, []string{"nginx", "permission"}),
		waf(`waf-nginxgeneric-hdr`, `Nginxgeneric WAF detected (headers)`, `(?i)nginx|(?i)you.do(not|n.t)?.have.permission.to.access.this.document`, TargetResponseHeader, []string{"nginx", "permission"}),
		waf(`waf-stackpath`, `Stackpath WAF detected`, `(?i)action.that.triggered.the.service.and.blocked|(?i)<h2>sorry,.you.have.been.blocked.?<.h2>`, TargetResponseBody, []string{"triggered", "blocked"}),
		waf(`waf-stackpath-hdr`, `Stackpath WAF detected (headers)`, `(?i)action.that.triggered.the.service.and.blocked|(?i)<h2>sorry,.you.have.been.blocked.?<.h2>`, TargetResponseHeader, []string{"triggered", "blocked"}),
		waf(`waf-sabre`, `Sabre WAF detected`, `(?i)dxsupport@sabre.com`, TargetResponseBody, []string{"dxsupport"}),
		waf(`waf-sabre-hdr`, `Sabre WAF detected (headers)`, `(?i)dxsupport@sabre.com`, TargetResponseHeader, []string{"dxsupport"}),
		waf(`waf-wordfence`, `Wordfence WAF detected`, `(?i)generated.by.wordfence|(?i)your.access.to.this.site.has.been.limited|(?i).>wordfence<.`, TargetResponseBody, []string{"generated", "limited", "wordfence"}),
		waf(`waf-wordfence-hdr`, `Wordfence WAF detected (headers)`, `(?i)generated.by.wordfence|(?i)your.access.to.this.site.has.been.limited|(?i).>wordfence<.`, TargetResponseHeader, []string{"generated", "limited", "wordfence"}),
		waf(`waf-360`, `360 WAF detected`, `(?i).wzws.waf.cgi.|(?i)wangzhan\.360\.cn|(?i)qianxin.waf|(?i)360wzws|(?i)transfer.is.blocked`, TargetResponseBody, []string{"wzws", "wangzhan", "qianxin", "360wzws", "transfer"}),
		waf(`waf-360-hdr`, `360 WAF detected (headers)`, `(?i).wzws.waf.cgi.|(?i)wangzhan\.360\.cn|(?i)qianxin.waf|(?i)360wzws|(?i)transfer.is.blocked`, TargetResponseHeader, []string{"wzws", "wangzhan", "qianxin", "360wzws", "transfer"}),
		waf(`waf-asm`, `Asm WAF detected`, `(?i)the.requested.url.was.rejected..please.consult.with.your.administrator.`, TargetResponseBody, []string{"administrator"}),
		waf(`waf-asm-hdr`, `Asm WAF detected (headers)`, `(?i)the.requested.url.was.rejected..please.consult.with.your.administrator.`, TargetResponseHeader, []string{"administrator"}),
		waf(`waf-rsfirewall`, `Rsfirewall WAF detected`, `(?i)com.rsfirewall.403.forbidden|(?i)com.rsfirewall.event|(?i)(\b)?rsfirewall(\b)?|(?i)rsfirewall`, TargetResponseBody, []string{"rsfirewall"}),
		waf(`waf-rsfirewall-hdr`, `Rsfirewall WAF detected (headers)`, `(?i)com.rsfirewall.403.forbidden|(?i)com.rsfirewall.event|(?i)(\b)?rsfirewall(\b)?|(?i)rsfirewall`, TargetResponseHeader, []string{"rsfirewall"}),
		waf(`waf-sucuri`, `Sucuri WAF detected`, `(?i)access.denied.-.sucuri.website.firewall|(?i)sucuri.webSite.firewall.-.cloudProxy.-.access.denied|(?i)questions\?.+cloudproxy@sucuri\.net|(?i)http(s)?.\/\/(cdn|supportx.)?sucuri(.net|com)?`, TargetResponseBody, []string{"firewall", "cloudproxy", "sucuri"}),
		waf(`waf-sucuri-hdr`, `Sucuri WAF detected (headers)`, `(?i)access.denied.-.sucuri.website.firewall|(?i)sucuri.webSite.firewall.-.cloudProxy.-.access.denied|(?i)questions\?.+cloudproxy@sucuri\.net|(?i)http(s)?.\/\/(cdn|supportx.)?sucuri(.net|com)?`, TargetResponseHeader, []string{"firewall", "cloudproxy", "sucuri"}),
		waf(`waf-airlock`, `Airlock WAF detected`, `(?i)\Aal[.-]?(sess|lb)=?`, TargetResponseHeader, nil),
		waf(`waf-xuanwudun`, `Xuanwudun WAF detected`, `(?i)class=.(db)?waf.?(-row.)?>`, TargetResponseBody, []string{"class"}),
		waf(`waf-xuanwudun-hdr`, `Xuanwudun WAF detected (headers)`, `(?i)class=.(db)?waf.?(-row.)?>`, TargetResponseHeader, []string{"class"}),
		waf(`waf-chuangyudun`, `Chuangyudun WAF detected`, `(?i)(http(s)?.//(www.)?)?365cyd.(com|net)`, TargetResponseBody, []string{"365cyd"}),
		waf(`waf-chuangyudun-hdr`, `Chuangyudun WAF detected (headers)`, `(?i)(http(s)?.//(www.)?)?365cyd.(com|net)`, TargetResponseHeader, []string{"365cyd"}),
		waf(`waf-securesphere`, `Securesphere WAF detected`, `(?i)<td.class="(errormessage|error)".height="[0-9]{1,3}".width="[0-9]{1,3}">|(?i)the.incident.id.(is|number.is).`, TargetResponseBody, []string{"height", "incident"}),
		waf(`waf-securesphere-hdr`, `Securesphere WAF detected (headers)`, `(?i)<td.class="(errormessage|error)".height="[0-9]{1,3}".width="[0-9]{1,3}">|(?i)the.incident.id.(is|number.is).`, TargetResponseHeader, []string{"height", "incident"}),
		waf(`waf-anquanbao`, `Anquanbao WAF detected`, `(?i).aqb_cc.error.`, TargetResponseBody, []string{"aqb_cc"}),
		waf(`waf-anquanbao-hdr`, `Anquanbao WAF detected (headers)`, `(?i).aqb_cc.error.`, TargetResponseHeader, []string{"aqb_cc"}),
		waf(`waf-modsecurity`, `Modsecurity WAF detected`, `(?i)ModSecurity|NYOB|(?i)mod_security|(?i)this.error.was.generated.by.mod.security|(?i)web.server at|(?i)page.you.are.(accessing|trying)?.(to|is)?.(access)?.(is|to)?.(restricted)?|(?i)blocked.by.mod.security`, TargetResponseBody, []string{"modsecurity", "nyob", "mod_security", "generated", "server", "page", "security"}),
		waf(`waf-modsecurity-hdr`, `Modsecurity WAF detected (headers)`, `(?i)ModSecurity|NYOB|(?i)mod_security|(?i)this.error.was.generated.by.mod.security|(?i)web.server at|(?i)page.you.are.(accessing|trying)?.(to|is)?.(access)?.(is|to)?.(restricted)?|(?i)blocked.by.mod.security`, TargetResponseHeader, []string{"modsecurity", "nyob", "mod_security", "generated", "server", "page", "security"}),
		waf(`waf-modsecurityowasp`, `Modsecurityowasp WAF detected`, `(?i)additionally\S.a.406.not.acceptable`, TargetResponseBody, []string{"additionally"}),
		waf(`waf-modsecurityowasp-hdr`, `Modsecurityowasp WAF detected (headers)`, `(?i)additionally\S.a.406.not.acceptable`, TargetResponseHeader, []string{"additionally"}),
		waf(`waf-squid`, `Squid WAF detected`, `(?i)squid|(?i)Access control configuration prevents|(?i)X.Squid.Error`, TargetResponseBody, []string{"squid", "configuration"}),
		waf(`waf-squid-hdr`, `Squid WAF detected (headers)`, `(?i)squid|(?i)Access control configuration prevents|(?i)X.Squid.Error`, TargetResponseHeader, []string{"squid", "configuration"}),
		waf(`waf-shieldsecurity`, `Shieldsecurity WAF detected`, `(?i)blocked.by.the.shield|(?i)transgression(\(s\))?.against.this|(?i)url.{1,2}form.or.cookie.data.wasn.t.appropriate`, TargetResponseBody, []string{"blocked", "transgression", "appropriate"}),
		waf(`waf-shieldsecurity-hdr`, `Shieldsecurity WAF detected (headers)`, `(?i)blocked.by.the.shield|(?i)transgression(\(s\))?.against.this|(?i)url.{1,2}form.or.cookie.data.wasn.t.appropriate`, TargetResponseHeader, []string{"blocked", "transgression", "appropriate"}),
		waf(`waf-wallarm`, `Wallarm WAF detected`, `(?i)nginix.wallarm`, TargetResponseBody, []string{"wallarm"}),
		waf(`waf-wallarm-hdr`, `Wallarm WAF detected (headers)`, `(?i)nginix.wallarm`, TargetResponseHeader, []string{"wallarm"}),
		waf(`waf-huaweicloud`, `Huaweicloud WAF detected`, `(?i)HWWAFSESID=`, TargetResponseHeader, []string{"hwwafsesid"}),
		waf(`waf-safe3webfirewall`, `Safe3webfirewall WAF detected`, `(?i)safe3\ Web\ Firewall`, TargetResponseHeader, []string{"firewall"}),
		waf(`waf-squarespace`, `Squarespace WAF detected`, `(?i)Firewall_action`, TargetResponseHeader, []string{"firewall_action"}),
		waf(`waf-godaddywebprotection`, `Godaddywebprotection WAF detected`, `(?i)GoDaddy\ Security|seal\.godaddy\.com|GoDaddy\ security`, TargetResponseBody, []string{"security", "godaddy"}),
		waf(`waf-transipwebfirewall`, `Transipwebfirewall WAF detected`, `(?i)X\-TransIP\-Balancer`, TargetResponseHeader, []string{"balancer"}),
		waf(`waf-xlabssecuritywaf`, `Xlabssecuritywaf WAF detected`, `(?i)Secured:\ By\ XLabs\ Security`, TargetResponseHeader, []string{"security"}),
		waf(`waf-shieldonfirewall`, `Shieldonfirewall WAF detected`, `(?i)X\-Protected\-By:\ shieldon\.io`, TargetResponseHeader, []string{"protected"}),
	}
}
