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
	"slices"
	"testing"

	"github.com/hashicorp/go-multierror"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestParseReportingEndpoints(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected []string
		Error    bool
	}{
		"blank": {
			Input:    "",
			Expected: []string{},
			Error:    true,
		},
		`missing-=`: {
			Input:    `endpoint-1 "https://example.com/reports"`,
			Expected: []string{},
			Error:    true,
		},
		`missing-url`: {
			Input:    `endpoint-1=`,
			Expected: []string{},
			Error:    true,
		},
		`missing-key`: {
			Input:    `="https://example.com/reports"`,
			Expected: []string{},
			Error:    true,
		},
		`key-has-invalid-characters`: {
			Input:    `endpoint:1="https://example.com/reports"`,
			Expected: []string{},
			Error:    true,
		},
		`url-missing-l-quote`: {
			Input:    `endpoint-1=https://example.com/reports"`,
			Expected: []string{},
			Error:    true,
		},
		`url-missing-r-quote`: {
			Input:    `endpoint-1="https://example.com/reports`,
			Expected: []string{},
			Error:    true,
		},
		`url-missing-both-quotes`: {
			Input:    `endpoint-1=https://example.com/reports`,
			Expected: []string{},
			Error:    true,
		},
		`url-using-single-quotes`: {
			Input:    `endpoint-1='https://example.com/reports'`,
			Expected: []string{},
			Error:    true,
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

			actual, err := ParseReportingEndpoint(tc.Input)
			if err != nil && tc.Error == false {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						t.Errorf("Error: %v", e)
					}
				} else {
					t.Errorf("Error: %v", err)
				}
			}

			actualKeys := maps.Keys(actual)

			assert.Truef(slices.Equal(tc.Expected, actualKeys), "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}
