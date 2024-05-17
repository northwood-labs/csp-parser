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
)

// Parse takes a string and returns a map of CSP directives and their values.
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

		if len(kv) > 0 {
			key = kv[0]
			values = kv[1:]
		}

		switch strings.ToLower(key) {
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

			// https://www.w3.org/TR/CSP2/#directive-frame-src
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"directive `%s` is deprecated; governing nested browsing contexts SHOULD "+
						"use the `child-src` directive instead [CSP2]",
					key,
				),
			)
		case "img-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ImageSource = append(parsedPolicy.ImageSource, *listItem)
		case "media-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.MediaSource = append(parsedPolicy.MediaSource, *listItem)
		case "object-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ObjectSource = append(parsedPolicy.ObjectSource, *listItem)
		case "script-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.ScriptSource = append(parsedPolicy.ScriptSource, *listItem)
		case "style-src":
			errs = multierror.Append(errs, handleSourceExpr(values, key, listItem))
			parsedPolicy.StyleSource = append(parsedPolicy.StyleSource, *listItem)

		case "frame-ancestors":
		case "plugin-types":
		case "report-uri":
		case "sandbox":
		default:
			errs = multierror.Append(errs, fmt.Errorf("unknown directive `%s`", key))
		}
	}

	return parsedPolicy, errs.ErrorOrNil()
}

// isBase64 doesn't try to decode anything. Rather, it just checks if the string
// matches the allowed list of characters. A value of `true` means that he
// string is *probably* base64-encoded. A value of `false` means that the string
// is definitely not base64-encoded.
//
// base64-value = 1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )
func isBase64(s string) bool {
	reBase64 := regexp.MustCompile(`^[a-zA-Z0-9+/]*={0,2}$`)

	return reBase64.MatchString(s) && len(s) > 0
}

// isAlphaDigit checks if the string is entirely ASCII, excluding non-printable
// characters (e.g., NUL, DEL). A value of `true` means that the string is
// comprised entirely of printable ASCII characters. A value of `false` means
// that the string contains non-printable or non-ASCII characters.
func isAlphaDigit(s string) bool {
	reASCII := regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	return reASCII.MatchString(s)
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
// host-source = [ scheme-part "://" ] host-part [ port-part ] [ path-part ]
// scheme-part = <scheme production from RFC 3986, section 3.1>
// host-part   = "*" / [ "*." ] 1*host-char *( "." 1*host-char )
// host-char   = ALPHA / DIGIT / "-"
// path-part   = <path production from RFC 3986, section 3.3>
// port-part   = ":" ( 1*DIGIT / "*" )
//
// https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
// https://www.w3.org/TR/CSP2/#match-source-expression
// https://regex101.com/r/63rDiN/1
func isHostSource(s string) bool {
	reHostSource := regexp.MustCompile(
		`^([a-zA-Z][a-zA-Z0-9+-.]*://)?(\*|(\*)?\.?([a-zA-Z0-9-]+))+(:(\*|[0-9]+))?(/[^/]+)*$`,
	)

	return reHostSource.MatchString(s)
}

// isKeywordSource checks if the string matches the keywords and quotations
// below.
//
// keyword-source = "'self'" / "'unsafe-inline'" / "'unsafe-eval'"
func isKeywordSource(s string) bool {
	return strings.EqualFold(s, `'self'`) || strings.EqualFold(s, `'unsafe-inline'`) ||
		strings.EqualFold(s, `'unsafe-eval'`)
}

// isNonceSource checks if the string matches the patterns below.
//
// nonce-value  = base64-value
// nonce-source = "'nonce-" nonce-value "'"
func isNonceSource(s string) bool {
	reNonceSource := regexp.MustCompile(`^'nonce-[a-zA-Z0-9+/]*={0,2}'$`)

	return reNonceSource.MatchString(s) && len(s) > 9
}

// isHashSource checks if the string matches the patterns below.
//
// hash-value  = base64-value
// hash-algo   = "sha256" / "sha384" / "sha512"
// hash-source = "'" hash-algo "-" hash-value "'"
func isHashSource(s string) bool {
	reHashSource := regexp.MustCompile(`^'sha(256|384|512)-[a-zA-Z0-9+/]*={0,2}'$`)

	return reHashSource.MatchString(s) && len(s) > 10
}

// isMediaType checks if the string matches the patterns used in the IANA
// Registered Media Types document.
// https://www.iana.org/assignments/media-types/media-types.xhtml
func isMediaType(s string) bool {
	reMediaType := regexp.MustCompile(
		`^(application|audio|font|example|image|message|model|multipart|text|video)/[a-zA-Z0-9_-./+]+$`,
	)

	return reMediaType.MatchString(s)
}

func handleSourceExpr(values []string, key string, listItem *SourceListItem) error {
	var errs *multierror.Error

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

// As defined above, special URL schemes that refer to specific pieces of unique
// content, such as "data:", "blob:" and "filesystem:" are excluded from
// matching a policy of * and must be explicitly listed.

// Especially for the default-src and script-src directives, policy authors
// should be aware that allowing "data:" URLs is equivalent to unsafe-inline and
// allowing "blob:" or "filesystem:" URLs is equivalent to unsafe-eval.

// 4.2.2.3. Paths and Redirects

// In order to protect against Cross-Site Scripting (XSS), web application
// authors SHOULD include: both the script-src and object-src directives, or
// include a default-src directive, which covers both scripts and plugins.

// In either case, authors SHOULD NOT include either 'unsafe-inline' or data: as
// valid sources in their policies. Both enable XSS attacks by allowing code to
// be included directly in the document itself; they are best avoided
// completely.

// connect-src example.com
// All of the following will fail with the preceding directive in place:
// * new WebSocket("wss://evil.com/");
// * (new XMLHttpRequest()).open("GET", "https://evil.com/", true);
// * new EventSource("https://evil.com");

// 7.7.2. Multiple Host Source Values
