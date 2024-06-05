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
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/northwood-labs/golang-utils/grammar"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestParseReportingEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		Input       string
		Expected    []string
		Error       bool
		ErrorSubstr string
	}{
		"blank": {
			Input:    "",
			Expected: []string{},
			Error:    false,
		},
		`missing-= (1)`: {
			Input:       `endpoint-1 "https://example.com/reports"`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1` does not contain an `=` character",
		},
		`missing-= (2)`: {
			Input:       `endpoint-1 "https://example.com/reports"`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `\"https://example.com/reports\"` does not contain an `=` character",
		},
		`missing-url`: {
			Input:       `endpoint-1=`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1=` is missing a URL",
		},
		`missing-key`: {
			Input:       `="https://example.com/reports"`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `=\"https://example.com/reports\"` is missing a key",
		},
		`key-has-invalid-characters`: {
			Input:       `endpoint:1="https://example.com/reports"`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint:1=\"https://example.com/reports\"` has a key with invalid characters",
		},
		`url-missing-l-quote`: {
			Input:       `endpoint-1=https://example.com/reports"`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1=https://example.com/reports\"` URL is not enclosed in double quotes",
		},
		`url-missing-r-quote`: {
			Input:       `endpoint-1="https://example.com/reports`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1=\"https://example.com/reports` URL is not enclosed in double quotes",
		},
		`url-missing-both-quotes`: {
			Input:       `endpoint-1=https://example.com/reports`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1=https://example.com/reports` URL is not enclosed in double quotes",
		},
		`url-using-single-quotes`: {
			Input:       `endpoint-1='https://example.com/reports'`,
			Expected:    []string{},
			Error:       true,
			ErrorSubstr: "token-pair `endpoint-1='https://example.com/reports'` URL is not enclosed in double quotes",
		},
		`valid-single-tokenpair`: {
			Input:    `endpoint-1="https://example.com/reports"`,
			Expected: []string{"endpoint-1"},
			Error:    false,
		},
		`duplicate-keys`: {
			Input:    `endpoint-1="https://example.com/reports1" endpoint-1="https://example.com/reports2"`,
			Expected: []string{"endpoint-1"},
			Error:    false,
		},
		`valid-multiple-tokenpairs`: {
			Input:    `endpoint-1="https://example.com/reports1" endpoint-2="https://example.com/reports2"`,
			Expected: []string{"endpoint-1", "endpoint-2"},
			Error:    false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			containsErrorMessage := false
			errorCount := 0

			actual, err := ParseReportingEndpoint(tc.Input)
			if err != nil && tc.Error == true {
				if merr, ok := err.(*multierror.Error); ok {
					errorCount = len(merr.Errors)

					for _, e := range merr.Errors {
						// t.Error(e)

						if strings.Contains(e.Error(), tc.ErrorSubstr) {
							containsErrorMessage = true
						}
					}
				}
			} else if err != nil && tc.Error == false {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						t.Errorf("Error: %v", e)
					}
				} else {
					t.Errorf("Error: %v", err)
				}
			}

			if tc.Error == true && errorCount > 0 && !containsErrorMessage {
				t.Errorf(
					"Test '%v' contained %s, but none of those error messages contained `%s`.",
					name,
					func() string {
						return fmt.Sprintf(
							"%d %s",
							errorCount,
							grammar.Pluralize(errorCount, "error", "errors"),
						)
					}(),
					tc.ErrorSubstr,
				)
			}

			actualKeys := maps.Keys(actual)
			sort.Strings(actualKeys)

			assert.Truef(slices.Equal(tc.Expected, actualKeys), "Expected `%v`, but got `%v`.", tc.Expected, actualKeys)
		})
	}
}
