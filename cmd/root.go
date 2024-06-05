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
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/hashicorp/go-multierror"
	clihelpers "github.com/northwood-labs/cli-helpers"
	"github.com/northwood-labs/csp-parser/csp"
	"github.com/spf13/cobra"
)

var (
	fCurrentURL         string
	fReportingEndpoints string
	fJSON               bool
	fVerbose            bool

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

		This is intended to be a conforming parser and evaluator for CSP as defined in
		the W3C specifications. Supports CSP Level 2 as well as the 2024-04-24 working
		draft of CSP Level 3.

		CSP policies are passed as ARGUMENTS. There is commonly only one, but multiple
		are supported. From the command line, we recommend wrapping the entire policy in
		double-quotes since CSP policies often contain single-quoted values.`),
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			out, err := csp.Parse(fCurrentURL, fReportingEndpoints, args)
			if err != nil {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						handleErrorMsg(e)
					}
				} else {
					handleErrorMsg(err)
				}
			}

			jsonb, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				logger.Fatalf("%v", err)
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
	rootCmd.Flags().
		StringVarP(&fCurrentURL, "current-url", "u", "", "The current URL being evaluated. May be an empty string, "+
			"but this will disable validation of 'self' sources.")
	rootCmd.Flags().
		StringVarP(&fReportingEndpoints, "reporting-endpoints", "e", "", "The value of the Reporting-Endpoints "+
			"header, used to validate the 'report-to' directive. If there is no 'report-to' directive, "+
			"this value may be empty.")

	rootCmd.PersistentFlags().BoolVarP(&fJSON, "json", "j", false, "Return results in JSON format.")
	rootCmd.PersistentFlags().BoolVarP(&fVerbose, "verbose", "v", false, "Print verbose output.")
}

func handleErrorMsg(e error) {
	switch {
	case strings.HasPrefix(e.Error(), "[ERROR]"):
		logger.Errorf("%v", e.Error()[8:])
	case strings.HasPrefix(e.Error(), "[WARN]"):
		logger.Warnf("%v", e.Error()[7:])
	case strings.HasPrefix(e.Error(), "[INFO]"):
		logger.Infof("%v", e.Error()[7:])
	default:
		logger.Errorf("%v", e.Error())
	}
}
