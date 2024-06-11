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

// ParseReportingEndpoint checks the syntax of the `Reporting-Endpoints` header.
func ParseReportingEndpoint(s string) (map[string]string, error) {
	var (
		values map[string]string
		errs   *multierror.Error
	)

	values = make(map[string]string)
	tokenPairList := strings.Split(s, ",")

	for i := range tokenPairList {
		tokenPair := strings.TrimSpace(tokenPairList[i])

		if tokenPair == "" {
			continue
		}

		if !strings.Contains(tokenPair, "=") {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` does not contain an `=` character",
					tokenPair,
				),
			)

			continue
		}

		if strings.Contains(tokenPair, " ") {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] `%s` appears to be missing a comma between token-pairs",
					tokenPair,
				),
			)

			continue
		}

		token := strings.Split(tokenPair, "=")
		if len(token) != 2 {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` is missing either a key or value",
					tokenPair,
				),
			)

			continue
		}

		key := token[0]
		if key == "" {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` is missing a key",
					tokenPair,
				),
			)

			continue
		}

		if !isValidToken(key) {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` has a key with invalid characters",
					tokenPair,
				),
			)

			continue
		}

		url := token[1]
		if url == "" {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` is missing a URL",
					tokenPair,
				),
			)

			continue
		}

		if url[0:1] != "\"" || url[len(url)-1:] != "\"" {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` URL is not enclosed in double quotes",
					tokenPair,
				),
			)

			continue
		}

		url = url[1 : len(url)-1]

		if !isValidReportingURL(url) {
			errs = multierror.Append(
				errs,
				fmt.Errorf(
					"[ERROR] token-pair `%s` URL is not a valid URL",
					tokenPair,
				),
			)

			continue
		}

		values[key] = url
	}

	return values, errs.ErrorOrNil()
}

// isValidToken verifies that this is a valid token per the Reporting API
// (editor's draft) specification.
//
// At the moment, a "token" is under-defined. However, RFC 9110 gives us the
// following definition. This is what the CSP Level 3 (draft) specification
// references, even though the Reporting API (editor's draft) does not.
//
// <https://w3c.github.io/reporting/#concept-endpoints>
// <https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2>
func isValidToken(s string) bool {
	reToken := regexp.MustCompile("^[0-9a-zA-Z!#$%&'*+-.^_`|~]+$")

	return reToken.MatchString(s)
}
