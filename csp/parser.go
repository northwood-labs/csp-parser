// Copyright 2024, Northwood Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/nlnwa/whatwg-url/url"
)

/*
Parse parses a Content Security Policy (CSP) string and returns a Policy
struct.

----

  - currentURL (string): The URL of the current document. May be an empty
    string, but this will disable validation of 'self' sources.

  - reportingEndpointsHeader (string): The value of the `Reporting-Endpoints`
    header. Is used to validate the `report-to` directive. If there is no
    `report-to` directive, this value can be an empty string.

  - policies ([]string): A slice of strings, each representing the value of a
    `Content-Security-Policy` header. Normally, there will only be one. However
    there are specific rules to apply when combining multiple policies.
*/
func Parse(currentURL, reportingEndpointsHeader string, policies []string) ([]*Policy, error) {
	var (
		key    string
		values []string
		errs   *multierror.Error

		reWhitespace   = regexp.MustCompile(`\s+`)
		parsedPolicies = []*Policy{}
	)

	if currentURL == "" {
		errs = multierror.Append(errs, fmt.Errorf(errCSP0001))
	}

	if reportingEndpointsHeader == "" {
		errs = multierror.Append(errs, fmt.Errorf(errCSP0002))
	}

	for j := range policies {
		policy := policies[j]

		rawDirectives := strings.Split(policy, ";")
		parsedPolicy := &Policy{}

		for i := range rawDirectives {
			directive := strings.TrimSpace(rawDirectives[i])

			// Bail out early if the directive is empty.
			// Or the last directive ends with a semicolon.
			if directive == "" {
				continue
			}

			directive = reWhitespace.ReplaceAllString(directive, " ")
			kv := strings.Split(directive, " ")
			listItem := &SourceListItem{}
			mediaTypeItem := &MediaTypeListItem{}
			urlReference := &URLRef{}
			reportingReference := &ReportingRef{}
			sandboxToken := &SandboxToken{}
			webrtcToken := &WebRTCToken{}
			ancestorListItem := &AncestorSourceListItem{}

			if len(kv) > 0 {
				key = kv[0]
				values = kv[1:]
			}

			switch strings.ToLower(key) {
			case "base-uri":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.BaseURI = append(parsedPolicy.BaseURI, *listItem)
			case "block-all-mixed-content":
				parsedPolicy.BlockAllMixedContent = true
				errs = multierror.Append(errs, fmt.Errorf(errCSP0801, key))
			case "child-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ChildSource = append(parsedPolicy.ChildSource, *listItem)
				errs = multierror.Append(errs, fmt.Errorf(errCSP0802, key))
			case "connect-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ConnectSource = append(parsedPolicy.ConnectSource, *listItem)
			case "default-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.DefaultSource = append(parsedPolicy.DefaultSource, *listItem)
			// case "fenced-frame-src":
			// @TODO
			case "font-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.FontSource = append(parsedPolicy.FontSource, *listItem)
			case "form-action":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.FormAction = append(parsedPolicy.FormAction, *listItem)
			case "frame-ancestors":
				errs = multierror.Append(errs, handleAncestorExpr(values, key, ancestorListItem))
				parsedPolicy.FrameAncestors = append(parsedPolicy.FrameAncestors, *ancestorListItem)
				// Error on 'unsafe-eval' or 'unsafe-inline'
			case "frame-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.FrameSource = append(parsedPolicy.FrameSource, *listItem)
			case "img-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ImageSource = append(parsedPolicy.ImageSource, *listItem)
			case "manifest-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ManifestSource = append(parsedPolicy.ManifestSource, *listItem)
			case "media-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.MediaSource = append(parsedPolicy.MediaSource, *listItem)
			case "navigate-to":
				errs = multierror.Append(errs, fmt.Errorf(errCSP0803, key))
			case "object-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ObjectSource = append(parsedPolicy.ObjectSource, *listItem)
			case "plugin-types":
				errs = multierror.Append(errs, handlePluginTypes(values, key, mediaTypeItem))
				parsedPolicy.PluginTypes = append(parsedPolicy.PluginTypes, *mediaTypeItem)
				errs = multierror.Append(errs, fmt.Errorf(errCSP0804, key))
			case "prefetch-src":
				errs = multierror.Append(errs, fmt.Errorf(errCSP0803, key))
			case "referrer":
				errs = multierror.Append(errs, fmt.Errorf(errCSP0803, key))
			case "report-to":
				value := ""
				if len(values) != 1 {
					errs = multierror.Append(errs, fmt.Errorf(errCSP0501, key))
				}

				value = values[0]
				errs = multierror.Append(errs, handleReportTo(value, key, reportingEndpointsHeader, reportingReference))
				parsedPolicy.ReportTo = append(parsedPolicy.ReportTo, *reportingReference)
			case "report-uri":
				errs = multierror.Append(errs, handleReportingURLs(values, key, urlReference))
				parsedPolicy.ReportURI = append(parsedPolicy.ReportURI, *urlReference)
				errs = multierror.Append(errs, fmt.Errorf(errCSP0805, key))
			// case "require-trusted-types-for":
			// @TODO
			case "sandbox":
				errs = multierror.Append(errs, handleSandbox(values, key, sandboxToken))
				parsedPolicy.Sandbox = append(parsedPolicy.Sandbox, *sandboxToken)
			case "script-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ScriptSource = append(parsedPolicy.ScriptSource, *listItem)
			case "script-src-attr":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ScriptSourceAttr = append(parsedPolicy.ScriptSourceAttr, *listItem)
			case "script-src-elem":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.ScriptSourceElem = append(parsedPolicy.ScriptSourceElem, *listItem)
			case "style-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.StyleSource = append(parsedPolicy.StyleSource, *listItem)
			case "style-src-attr":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.StyleSourceAttr = append(parsedPolicy.StyleSourceAttr, *listItem)
			case "style-src-elem":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.StyleSourceElem = append(parsedPolicy.StyleSourceElem, *listItem)
			// case "trusted-types":
			// @TODO
			case "upgrade-insecure-requests":
				parsedPolicy.UpgradeInsecureReq = true
			case "webrtc":
				value := ""
				if len(values) != 1 {
					errs = multierror.Append(errs, fmt.Errorf(errCSP0601, key))
				}

				value = values[0]
				errs = multierror.Append(errs, handleWebRTC(value, key, webrtcToken))
				parsedPolicy.WebRTC = *webrtcToken
			case "worker-src":
				errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
				parsedPolicy.WorkerSource = append(parsedPolicy.WorkerSource, *listItem)
			default:
				errs = multierror.Append(errs, fmt.Errorf(errCSP0901, key))
			}
		}

		parsedPolicies = append(parsedPolicies, parsedPolicy)
	}

	return parsedPolicies, errs.ErrorOrNil()
}

/*
isSchemeSource checks whether or not the string matches the defined pattern for
the scheme of a URL, as defined in RFC 3986 §3.1.

https://datatracker.ietf.org/doc/html/rfc3986#section-3.1

----

  - s (string): The value that will be evaluated.
*/
func isSchemeSource(s string) bool {
	// scheme_part   = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	// scheme-source = scheme-part ":"
	reSchemePart := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+-.]*:$`)

	return reSchemePart.MatchString(s)
}

/*
isHostSource checks whether or not the string matches the defined pattern as
documented below. See CSP Level 2, § 4.2.2. "Matching Source Expressions"

  - https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
  - https://www.w3.org/TR/CSP2/#match-source-expression
  - https://regex101.com/r/63rDiN/1

----

  - s (string): The value that will be evaluated.
*/
func isHostSource(s string) bool {
	// host-source = [ scheme-part "://" ] host-part [ ":" port-part ] [ path-part ]
	// scheme_part = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	// host-part   = "*" / [ "*." ] 1*host-char *( "." 1*host-char ) [ "." ]
	// host-char   = ALPHA / DIGIT / "-"
	// path-part   = <https://datatracker.ietf.org/doc/html/rfc3986#section-3.3>
	// port-part   = 1*DIGIT / "*"
	reHostSource := regexp.MustCompile(
		`^([a-zA-Z][a-zA-Z0-9+-.]*://)?(\*|(\*)?\.?([a-zA-Z0-9-]+))+(:(\*|[0-9]+))?(/[^/]+)*$`,
	)

	reIPv4Dumb := regexp.MustCompile(`^(([0-9]{1,3}[.]){3}[0-9]{1,3})$`)

	return s == "127.0.0.1" || (reHostSource.MatchString(s) && !reIPv4Dumb.MatchString(s))
}

/*
isValidIPv4 checks whether or not the string is a valid IPv4 address. Allows IP
"addresses" that are part of CIDR syntax (e.g., `.0`).

  - https://regex101.com/r/9mNoiZ/1

----

  - s (string): The value that will be evaluated.
*/
func isValidIPv4(s string) bool {
	reIPv4 := regexp.MustCompile(
		`^(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]` +
			`(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})$`,
	)

	return reIPv4.MatchString(s)
}

/*
isKeywordSource checks whether or not the string matches the keywords and
quotations below.

	'self', 'report-sample', 'strict-dynamic', 'unsafe-eval', 'unsafe-hashes',
	'unsafe-inline', 'unsafe-allow-redirects', 'wasm-unsafe-eval'

https://www.w3.org/TR/2024/WD-CSP3-20240424/#grammardef-keyword-source

----

  - s (string): The value that will be evaluated.
*/
func isKeywordSource(s string) bool {
	return strings.EqualFold(s, `'self'`) ||
		strings.EqualFold(s, `'report-sample'`) ||
		strings.EqualFold(s, `'strict-dynamic'`) ||
		strings.EqualFold(s, `'unsafe-eval'`) ||
		strings.EqualFold(s, `'unsafe-hashes'`) ||
		strings.EqualFold(s, `'unsafe-inline'`) ||
		strings.EqualFold(s, `'unsafe-allow-redirects'`) ||
		strings.EqualFold(s, `'wasm-unsafe-eval'`)
}

/*
isSandboxSource checks whether or not the string matches the keywords below.

	allow-forms, allow-pointer-lock, allow-popups, allow-same-origin,
	allow-scripts, allow-top-navigation

https://www.w3.org/TR/CSP2/#sandbox-usage

----

  - s (string): The value that will be evaluated.
*/
func isSandboxSource(s string) bool {
	return strings.EqualFold(s, `allow-downloads`) ||
		strings.EqualFold(s, `allow-forms`) ||
		strings.EqualFold(s, `allow-modals`) ||
		strings.EqualFold(s, `allow-orientation-lock`) ||
		strings.EqualFold(s, `allow-pointer-lock`) ||
		strings.EqualFold(s, `allow-popups`) ||
		strings.EqualFold(s, `allow-popups-to-escape-sandbox`) ||
		strings.EqualFold(s, `allow-presentation`) ||
		strings.EqualFold(s, `allow-same-origin`) ||
		strings.EqualFold(s, `allow-scripts`) ||
		strings.EqualFold(s, `allow-top-navigation`) ||
		strings.EqualFold(s, `allow-top-navigation-by-user-activation`) ||
		strings.EqualFold(s, `allow-top-navigation-to-custom-protocols`)
}

/*
isNonceSource checks whether or not the string matches the required pattern.

----

  - s (string): The value that will be evaluated.
*/
func isNonceSource(s string) bool {
	// nonce-value  = base64-value
	// nonce-source = "'nonce-" nonce-value "'"
	reNonceSource := regexp.MustCompile(`^(?i)'nonce-[a-zA-Z0-9+/]*={0,2}'$`)

	return reNonceSource.MatchString(s) && len(s) > 9
}

/*
isHashSource checks whether or not the string matches the required pattern.

----

  - s (string): The value that will be evaluated.
*/
func isHashSource(s string) bool {
	// hash-value  = base64-value
	// hash-algo   = "sha256" / "sha384" / "sha512"
	// hash-source = "'" hash-algo "-" hash-value "'"
	reHashSource := regexp.MustCompile(`^(?i)'sha(256|384|512)-[a-zA-Z0-9+/]*={0,2}'$`)

	return reHashSource.MatchString(s) && len(s) > 10
}

/*
isMediaType checks whether or not the string matches the patterns used in the
IANA Registered Media Types document.

  - https://www.iana.org/assignments/media-types/media-types.xhtml

----

  - s (string): The value that will be evaluated.
*/
func isMediaType(s string) bool {
	reMediaType := regexp.MustCompile(
		`^(?i)(application|audio|font|example|image|message|model|multipart|text|video)/[a-zA-Z0-9_./+-]+$`,
	)

	return reMediaType.MatchString(s)
}

/*
isValidReportingURL checks whether or not the string is a valid URL that can be
used as a reporting URL. Implements the URL Living Standard (as of 2023-05-24).

  - https://url.spec.whatwg.org/commit-snapshots/eee49fdf4f99d59f717cbeb0bce29fda930196d4/

----

  - s (string): The value that will be evaluated.
*/
func isValidReportingURL(s string) bool {
	url, err := url.Parse(s)
	if err != nil {
		return false
	}

	// URL fragment is not allowed.
	if url.Href(true) != url.Href(false) {
		return false
	}

	return true
}

/*
isWebRTCSource checks whether or not the string matches the required pattern.

----

  - s (string): The value that will be evaluated.
*/
func isWebRTCSource(s string) bool {
	return strings.EqualFold(s, `'allow'`) || strings.EqualFold(s, `'block'`)
}

/*
handleSourceExpr handles the "source expression" type for the various
directives. Given a common CSP directive:

	directive value1 value2 value3 value4

…this function will parse the values and determine if they are valid source
expressions. If they are, they will be added to the SourceListItem struct.

----

  - values ([]string): A slice of strings, each representing a value for the
    directive. (value*, above)

  - key (string): The name of the directive. (directive, above)

  - listItem (*SourceListItem): A pointer to the SourceListItem struct that will
    be populated with the source expressions. This acts as a "collector".
*/
func handleSourceExpr(values []string, key string, listItem *SourceListItem) error {
	var errs *multierror.Error

	// source-expression = scheme-source / host-source / keyword-source
	//                     / nonce-source / hash-source
	for i := range values {
		switch {
		case values[i] == `'none'`:
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				None: true,
			})
		case isSchemeSource(values[i]):
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				SchemeSource: values[i],
			})
		case isHostSource(values[i]):
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				HostSource: values[i],
			})
		case isKeywordSource(values[i]):
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				KeywordSource: values[i],
			})
		case isNonceSource(values[i]):
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				NonceSource: values[i],
			})
		case isHashSource(values[i]):
			listItem.SourceExprs = append(listItem.SourceExprs, SourceExpr{
				HashSource: values[i],
			})
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0100]", key, values[i]),
			)
		}
	}

	return errs
}

/*
handleAncestorExpr handles the "ancestor expression" type for the
`frame-ancestors` directive. Given a common CSP directive:

	directive value1 value2 value3 value4

…this function will parse the values and determine if they are valid ancestor
expressions. If they are, they will be added to the AncestorSourceListItem
struct.

----

  - values ([]string): A slice of strings, each representing a value for the
    directive. (value*, above)

  - key (string): The name of the directive. (directive, above)

  - ancestorListItem (*AncestorSourceListItem): A pointer to the
    AncestorSourceListItem struct that will be populated with the ancestor
    expressions. This acts as a "collector".
*/
func handleAncestorExpr(values []string, key string, ancestorListItem *AncestorSourceListItem) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case values[i] == `'none'`:
			ancestorListItem.AncestorExprs = append(ancestorListItem.AncestorExprs, AncestorExpr{
				None: true,
			})
		case isSchemeSource(values[i]):
			ancestorListItem.AncestorExprs = append(ancestorListItem.AncestorExprs, AncestorExpr{
				SchemeSource: values[i],
			})
		case isHostSource(values[i]):
			ancestorListItem.AncestorExprs = append(ancestorListItem.AncestorExprs, AncestorExpr{
				HostSource: values[i],
			})
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0200]", key, values[i]),
			)
		}
	}

	return errs
}

/*
handlePluginTypes handles the "media type expression" type for the
`plugin-types` directive. Given a common CSP directive:

	directive value1 value2 value3 value4

…this function will parse the values and determine if they are valid media type
expressions. If they are, they will be added to the MediaTypeListItem struct.

----

  - values ([]string): A slice of strings, each representing a value for the
    directive. (value*, above)

  - key (string): The name of the directive. (directive, above)

  - mediaTypeItem (*MediaTypeListItem): A pointer to the MediaTypeListItem
    struct that will be populated with the media type expressions. This acts as
    a "collector".
*/
func handlePluginTypes(values []string, key string, mediaTypeItem *MediaTypeListItem) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case isMediaType(values[i]):
			mediaTypeItem.MediaTypes = append(mediaTypeItem.MediaTypes, values[i])
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0300]", key, values[i]),
			)
		}
	}

	return errs
}

/*
handleReportingURLs handles the "URL reference" type for the `report-uri`
directive. Given a common CSP directive:

	directive value1 value2 value3 value4

…this function will parse the values and determine if they are valid URL
references. If they are, they will be added to the URLRef struct.

----

  - values ([]string): A slice of strings, each representing a value for the
    directive. (value*, above)

  - key (string): The name of the directive. (directive, above)

  - urlReference (*URLRef): A pointer to the URLRef struct that will be
    populated with the URL references. This acts as a "collector".
*/
func handleReportingURLs(values []string, key string, urlReference *URLRef) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case isValidReportingURL(values[i]):
			urlReference.URLs = append(urlReference.URLs, values[i])
		default:
			url, err := url.Parse(values[i])
			if err != nil {
				errs = multierror.Append(
					errs,
					fmt.Errorf("[ERROR] directive `%s`: could not parse as a URL: `%s` [CSP-0401]", key, values[i]),
				)

				break
			}

			if url.Scheme() == "" {
				errs = multierror.Append(
					errs,
					fmt.Errorf(
						"[ERROR] directive `%s`: URL `%s` is missing a SCHEME, which is required [CSP-0402]",
						key,
						values[i],
					),
				)
			}

			if url.Fragment() != "" {
				errs = multierror.Append(
					errs,
					fmt.Errorf(
						"[ERROR] directive `%s`: URL `%s` includes a FRAGMENT, which is disallowed [CSP-0403]",
						key,
						values[i],
					),
				)
			}

			errs = multierror.Append(
				errs,
				fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0400]", key, values[i]),
			)
		}
	}

	return errs
}

func handleReportTo(value, key, reportingEndpointsHeader string, reportingRef *ReportingRef) error {
	var errs *multierror.Error

	endpointMap, err := ParseReportingEndpoint(reportingEndpointsHeader)
	if err != nil {
		if merr, ok := err.(*multierror.Error); ok {
			for _, e := range merr.Errors {
				errs = multierror.Append(errs, e)
			}
		}
	}

	if url, ok := endpointMap[value]; ok {
		reportingRef.Tokens = map[string]string{
			value: url,
		}
	} else {
		errs = multierror.Append(
			errs,
			fmt.Errorf("[ERROR] directive `%s` refers to undefined reporting endpoint `%s` [CSP-0502]", key, value),
		)
	}

	return errs
}

/*
handleSandbox handles the "sandbox expression" type for the `sandbox` directive.
Given a common CSP directive:

	directive value1 value2 value3 value4

…this function will parse the values and determine if they are valid sandbox
expressions. If they are, they will be added to the SandboxToken struct.

----

  - values ([]string): A slice of strings, each representing a value for the
    directive. (value*, above)

  - key (string): The name of the directive. (directive, above)

  - sandboxToken (*SandboxToken): A pointer to the SandboxToken struct that will
    be populated with the sandbox expressions. This acts as a "collector".
*/
func handleSandbox(values []string, key string, sandboxToken *SandboxToken) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case isSandboxSource(values[i]):
			sandboxToken.Allow = append(sandboxToken.Allow, values[i])
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0700]", key, values[i]),
			)
		}
	}

	return errs
}

/*
handleWebRTC handles the "webrtc value" type for the `webrtc` directive. Given a
webrtc CSP directive:

	webrtc 'allow'

…this function will parse the value and determine if it is a valid webrtc value.
If it is, it will be added to the WebRTCToken struct.

NOTE: This function works differently from most of the other `handle*` functions
in that it only accepts a single value.

----

  - value (string): A string representing a value for the `webrtc` directive.

  - key (string): The name of the directive. (directive, above)

  - webrtcToken (*WebRTCToken): A pointer to the WebRTCToken struct that will be
    populated with the webrtc value. This acts as a "collector".
*/
func handleWebRTC(value, key string, webrtcToken *WebRTCToken) error {
	var errs *multierror.Error

	switch {
	case isWebRTCSource(value):
		webrtcToken.Value = value
	default:
		errs = multierror.Append(
			errs,
			fmt.Errorf("[ERROR] directive `%s` has an invalid value `%s` [CSP-0600]", key, value),
		)
	}

	return errs
}
