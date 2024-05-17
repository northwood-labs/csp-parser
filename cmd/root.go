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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/hashicorp/go-multierror"
	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/csp-parser/csp"
	"github.com/spf13/cobra"
)

var (
	fJSON    bool
	fVerbose bool

	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
		Prefix:          "csp-parser",
	})

	rootCmd = &cobra.Command{
		Use:   "csp-parser",
		Short: "Helps parse and evaluate Content Security Policies (CSPs).",
		Long: clihelpers.LongHelpText(`
		csp-parser

		Helps evaluate the security posture and best practices with Content Security
		Policies (CSPs).

		This is a conforming parser and evaluator for CSPs as defined in the W3C
		specification. Supports CSP Level 2 as well as the 2024-04-24 working draft of
		CSP Level 3.`),
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// pp := debug.GetSpew()

			out, err := csp.Parse(args[0])
			if err != nil {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						logger.Errorf("%v", e)
					}
				} else {
					logger.Errorf("%v", err)
				}
			}

			// pp.Dump(out)

			jsonb, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				logger.Errorf("%v", err)
			}

			fmt.Println(string(jsonb))
		},
	}
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&fJSON, "json", "j", false, "Return results in JSON format.")
	rootCmd.PersistentFlags().BoolVarP(&fVerbose, "verbose", "v", false, "Print verbose output.")
}
