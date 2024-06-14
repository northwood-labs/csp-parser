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

const (
	// Parser and evaluator configuration
	errCSP0001 = "[INFO] currentURL is empty, so validation of 'self' sources is disabled [CSP-0001]"
	errCSP0002 = "[INFO] reportingEndpointsHeader is empty, so validation of `report-to` is disabled [CSP-0002]"

	// Source expressions
	errCSP0100 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0100]"

	// Ancestor expressions
	errCSP0200 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0200]"

	// Plugin types
	errCSP0300 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0300]"

	// Reporting URLs
	errCSP0400 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0400]"
	errCSP0401 = "[ERROR] directive `%s`: could not parse as a URL: `%s` [CSP-0401]"
	errCSP0402 = "[ERROR] directive `%s`: URL `%s` is missing a SCHEME, which is required [CSP-0402]"
	errCSP0403 = "[ERROR] directive `%s`: URL `%s` includes a FRAGMENT, which is disallowed [CSP-0403]"

	// Report-To directive and Reporting Endpoints header
	errCSP0501 = "[ERROR] directive `%s` may only have a single value [CSP-0501]"
	errCSP0502 = "[ERROR] directive `%s` refers to undefined reporting endpoint `%s` [CSP-0502]"
	errCSP0510 = "[ERROR] token-pair `%s` does not contain an `=` character [CSP-0510]"
	errCSP0511 = "[ERROR] `%s` appears to be missing a comma between token-pairs [CSP-0511]"
	errCSP0512 = "[ERROR] token-pair `%s` is missing either a key or value [CSP-0512]"
	errCSP0513 = "[ERROR] token-pair `%s` is missing a key [CSP-0513]"
	errCSP0514 = "[ERROR] token-pair `%s` has a key with invalid characters [CSP-0514]"
	errCSP0515 = "[ERROR] token-pair `%s` is missing a URL [CSP-0515]"
	errCSP0516 = "[ERROR] token-pair `%s` URL is not enclosed in double quotes [CSP-0516]"
	errCSP0517 = "[ERROR] token-pair `%s` URL is not a valid URL [CSP-0517]"

	// WebRTC
	errCSP0600 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0600]"
	errCSP0601 = "[ERROR] directive `%s` may only have a single value [CSP-0601]"

	// Sandboxing
	errCSP0700 = "[ERROR] directive `%s` has an invalid value `%s` [CSP-0700]"

	// Deprecations and obsoletions
	errCSP0801 = "[ERROR] directive `%s` is obsolete; use `upgrade-insecure-requests` instead [CSP-0801]"
	errCSP0802 = "[ERROR] directive `%s` is deprecated; use `frame-src` and/or `worker-src` instead [CSP-0802]"
	errCSP0803 = "[ERROR] directive `%s` was experimental in CSP3, but should now be removed from CSP policies [CSP-0803]"
	errCSP0804 = "[ERROR] directive `%s` is obsolete; remove this directive from the policy [CSP-0804]"
	errCSP0805 = "[WARN] directive `%s` is valid in CSP2, but will be deprecated in CSP3 [CSP-0805]"

	// Miscellaneous
	errCSP0901 = "[ERROR] unknown directive `%s` [CSP-0901]"
)
