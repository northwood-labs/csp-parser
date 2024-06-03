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

// Parse parses a Content Security Policy (CSP) string and returns a Policy
// struct.
func Parse(policy string) (*Policy, error) {
	var (
		key    string
		values []string
		errs   *multierror.Error
	)

	reWhitespace := regexp.MustCompile(`\s+`)
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
		urlReference := &URLReference{}
		sandboxToken := &SandboxToken{}
		webrtcToken := &WebRTCToken{}
		ancestorListItem := &AncestorSourceListItem{}

		if len(kv) > 0 {
			key = kv[0]
			values = kv[1:]
		}

		switch strings.ToLower(key) {
		case "block-all-mixed-content":
			parsedPolicy.BlockAllMixedContent = true
		case "upgrade-insecure-requests":
			parsedPolicy.UpgradeInsecureReq = true
		case "base-uri":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.BaseURI = append(parsedPolicy.BaseURI, *listItem)
		case "child-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ChildSource = append(parsedPolicy.ChildSource, *listItem)
		case "connect-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ConnectSource = append(parsedPolicy.ConnectSource, *listItem)
		case "default-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.DefaultSource = append(parsedPolicy.DefaultSource, *listItem)
		case "font-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.FontSource = append(parsedPolicy.FontSource, *listItem)
		case "form-action":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.FormAction = append(parsedPolicy.FormAction, *listItem)
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
		case "object-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ObjectSource = append(parsedPolicy.ObjectSource, *listItem)
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
		case "worker-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.WorkerSource = append(parsedPolicy.WorkerSource, *listItem)
		case "frame-ancestors":
			errs = multierror.Append(errs, handleAncestorExpr(values, key, ancestorListItem))
			parsedPolicy.FrameAncestors = append(parsedPolicy.FrameAncestors, *ancestorListItem)
		case "plugin-types":
			errs = multierror.Append(errs, handlePluginTypes(values, key, mediaTypeItem))
			parsedPolicy.PluginTypes = append(parsedPolicy.PluginTypes, *mediaTypeItem)
		// case "report-to":
		// 	errs = multierror.Append(errs, handleReportingURLs(values, key, urlReference))
		// 	parsedPolicy.ReportTo = append(parsedPolicy.ReportTo, *urlReference)
		case "report-uri":
			errs = multierror.Append(errs, handleReportingURLs(values, key, urlReference))
			parsedPolicy.ReportTo = append(parsedPolicy.ReportTo, *urlReference)

			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"directive `%s` is deprecated in CSP3 (Draft), but valid in CSP2; "+
						"use this along with `report-to` and the `Reporting-Endpoints` HTTP header for modern browsers; "+
						"see https://caniuse.com/mdn-http_headers_content-security-policy_report-to for best compat",
					key,
				),
			)
		case "sandbox":
			errs = multierror.Append(errs, handleSandbox(values, key, sandboxToken))
			parsedPolicy.Sandbox = append(parsedPolicy.Sandbox, *sandboxToken)
		case "webrtc":
			value := ""
			if len(values) != 1 {
				errs = multierror.Append(
					errs,
					fmt.Errorf("directive `%s` may only have a single value", key),
				)
			}

			value = values[0]
			errs = multierror.Append(errs, handleWebRTC(value, key, webrtcToken))
			parsedPolicy.WebRTC = *webrtcToken
		default:
			errs = multierror.Append(errs, fmt.Errorf("unknown directive `%s`", key))
		}
	}

	return parsedPolicy, errs.ErrorOrNil()
}

// isSchemeSource checks if the string matches the defined pattern for the
// scheme of a URL, as defined in RFC 3986 §3.1.
// https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
//
// scheme_part   = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
// scheme-source = scheme-part ":"
func isSchemeSource(s string) bool {
	reSchemePart := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+-.]*:$`)

	return reSchemePart.MatchString(s)
}

// isHostSource checks if the string matches the defined pattern as documented
// below. See CSP Level 2, § 4.2.2. "Matching Source Expressions"
//
// host-source = [ scheme-part "://" ] host-part [ ":" port-part ] [ path-part ]
// scheme_part = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
// host-part   = "*" / [ "*." ] 1*host-char *( "." 1*host-char ) [ "." ]
// host-char   = ALPHA / DIGIT / "-"
// path-part   = <https://datatracker.ietf.org/doc/html/rfc3986#section-3.3>
// port-part   = 1*DIGIT / "*"
//
// https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
// https://www.w3.org/TR/CSP2/#match-source-expression
// https://regex101.com/r/63rDiN/1
func isHostSource(s string) bool {
	reHostSource := regexp.MustCompile(
		`^([a-zA-Z][a-zA-Z0-9+-.]*://)?(\*|(\*)?\.?([a-zA-Z0-9-]+))+(:(\*|[0-9]+))?(/[^/]+)*$`,
	)

	reIPv4Dumb := regexp.MustCompile(`^(([0-9]{1,3}[.]){3}[0-9]{1,3})$`)

	return s == "127.0.0.1" || (reHostSource.MatchString(s) && !reIPv4Dumb.MatchString(s))
}

// isValidIPv4 checks if the string is a valid IPv4 address. Allows IP
// "addresses" that are part of CIDR syntax (e.g., `.0`).
//
// https://regex101.com/r/9mNoiZ/1
func isValidIPv4(s string) bool {
	reIPv4 := regexp.MustCompile(
		`^(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]` +
			`(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})$`,
	)

	return reIPv4.MatchString(s)
}

// isKeywordSource checks if the string matches the keywords and quotations
// below.
//
// <https://www.w3.org/TR/2024/WD-CSP3-20240424/#grammardef-keyword-source>
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

// isSandboxSource checks if the string matches the keywords below.
// <https://www.w3.org/TR/CSP2/#sandbox-usage>
func isSandboxSource(s string) bool {
	return strings.EqualFold(s, `allow-forms`) ||
		strings.EqualFold(s, `allow-pointer-lock`) ||
		strings.EqualFold(s, `allow-popups`) ||
		strings.EqualFold(s, `allow-same-origin`) ||
		strings.EqualFold(s, `allow-scripts`) ||
		strings.EqualFold(s, `allow-top-navigation`)
}

// isNonceSource checks if the string matches the patterns below.
//
// nonce-value  = base64-value
// nonce-source = "'nonce-" nonce-value "'"
func isNonceSource(s string) bool {
	reNonceSource := regexp.MustCompile(`^(?i)'nonce-[a-zA-Z0-9+/]*={0,2}'$`)

	return reNonceSource.MatchString(s) && len(s) > 9
}

// isHashSource checks if the string matches the patterns below.
//
// hash-value  = base64-value
// hash-algo   = "sha256" / "sha384" / "sha512"
// hash-source = "'" hash-algo "-" hash-value "'"
func isHashSource(s string) bool {
	reHashSource := regexp.MustCompile(`^(?i)'sha(256|384|512)-[a-zA-Z0-9+/]*={0,2}'$`)

	return reHashSource.MatchString(s) && len(s) > 10
}

// isMediaType checks if the string matches the patterns used in the IANA
// Registered Media Types document.
// https://www.iana.org/assignments/media-types/media-types.xhtml
func isMediaType(s string) bool {
	reMediaType := regexp.MustCompile(
		`^(?i)(application|audio|font|example|image|message|model|multipart|text|video)/[a-zA-Z0-9_./+-]+$`,
	)

	return reMediaType.MatchString(s)
}

// isValidReportingURL checks if the string is a valid URL that can be used as a
// reporting URL. Implements the URL Standard (as of 2023-05-24).
// https://url.spec.whatwg.org/commit-snapshots/eee49fdf4f99d59f717cbeb0bce29fda930196d4/
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

// isWebRTCSource checks if the string matches the keywords below.
func isWebRTCSource(s string) bool {
	return strings.EqualFold(s, `'allow'`) || strings.EqualFold(s, `'block'`)
}

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
				fmt.Errorf("directive `%s` has an invalid value `%s`", key, values[i]),
			)
		}
	}

	return errs
}

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
				fmt.Errorf("directive `%s` has an invalid value `%s`", key, values[i]),
			)
		}
	}

	return errs
}

func handlePluginTypes(values []string, key string, mediaTypeItem *MediaTypeListItem) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case isMediaType(values[i]):
			mediaTypeItem.MediaTypes = append(mediaTypeItem.MediaTypes, values[i])
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("directive `%s` has an invalid value `%s`", key, values[i]),
			)
		}
	}

	return errs
}

func handleReportingURLs(values []string, key string, urlReference *URLReference) error {
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
					fmt.Errorf("directive `%s`: could not parse as a URL: `%s`", key, values[i]),
				)

				break
			}

			if url.Scheme() == "" {
				errs = multierror.Append(
					errs,
					fmt.Errorf("directive `%s`: URL `%s` is missing a SCHEME, which is required", key, values[i]),
				)
			}

			if url.Fragment() != "" {
				errs = multierror.Append(
					errs,
					fmt.Errorf("directive `%s`: URL `%s` includes a FRAGMENT, which is disallowed", key, values[i]),
				)
			}

			errs = multierror.Append(
				errs,
				fmt.Errorf("directive `%s` has an invalid value `%s`", key, values[i]),
			)
		}
	}

	return errs
}

func handleSandbox(values []string, key string, sandboxToken *SandboxToken) error {
	var errs *multierror.Error

	for i := range values {
		switch {
		case isSandboxSource(values[i]):
			sandboxToken.Allow = append(sandboxToken.Allow, values[i])
		default:
			errs = multierror.Append(
				errs,
				fmt.Errorf("directive `%s` has an invalid value `%s`", key, values[i]),
			)
		}
	}

	return errs
}

func handleWebRTC(value, key string, webrtcToken *WebRTCToken) error {
	var errs *multierror.Error

	switch {
	case isWebRTCSource(value):
		webrtcToken.Value = value
	default:
		errs = multierror.Append(
			errs,
			fmt.Errorf("directive `%s` has an invalid value `%s`", key, value),
		)
	}

	return errs
}
