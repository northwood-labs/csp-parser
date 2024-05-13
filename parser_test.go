/*
Allow everything but only from the same origin
default-src 'self';

Only Allow Scripts from the same origin
script-src 'self';

Allow Google Analytics, Google AJAX CDN and Same Origin
script-src 'self' www.google-analytics.com ajax.googleapis.com;

This policy allows images, scripts, AJAX, form actions, and CSS from the same
origin, and does not allow any other resources to load (eg object, frame, media,
etc). It is a good starting point for many sites.
default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';base-uri 'self';form-action 'self'

One of the easiest ways to allow inline scripts when using CSP is to use a
nonce. A nonce is just a random, single use string value that you add to your
Content-Security-Policy header, like so:
script-src js-cdn.example.com 'nonce-rAnd0m';

A second approach to allow inline scripts is to use a hash, with this approach
you compute the hash of your JavaScript code, and put the value in our CSP
policy:
script-src js-cdn.example.com 'sha256-xzi4zkCjuC8lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='

One of the easiest ways to allow style tags when using CSP is to use a nonce. A
nonce is just a random, single use string value that you add to your
Content-Security-Policy header, like so:
style-src css-cdn.example.com 'nonce-rAnd0m';

A second approach to allow inline style is to use a hash, with this approach you
compute the hash of your <style> tag, and put the value in our CSP policy:
style-src css-cdn.example.com 'sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='
style-src 'self' 'unsafe-hashes' 'sha256-nMxMqdZhkHxz5vAuW/PAoLvECzzsmeAxD/BNwG15HuA=';

default-src 'self'; img-src https://images.example.com 'self';
default-src 'self';script-src 'self' static.cloudflareinsights.com
default-src 'none';script-src 'self' www.googletagmanager.com/gtag/js; connect-src www.google-analytics.com;
default-src 'self';font-src fonts.gstatic.com;style-src 'self' fonts.googleapis.com
script-src maps.googleapis.com;img-src data: maps.gstatic.com *.googleapis.com *.ggpht.com
script-src 'self' platform.twitter.com syndication.twitter.com; style-src 'self' 'sha256-5g0QXxO6NfvHJ6Uf5BK/hqQHtso8ZOdjlnbyKtYLvwc='; frame-src 'self' platform.twitter.com

https://content-security-policy.com/examples/multiple-csp-headers/

default-src 'self' blob: cdn.ryanparman.com; connect-src 'self' cdn.ryanparman.com embedr.flickr.com; frame-src cdn.ryanparman.com embed.music.apple.com platform.twitter.com syndication.twitter.com www.google.com www.instagram.com www.youtube.com; img-src 'self' 'unsafe-inline' data: cdn.ryanparman.com *.static.flickr.com *.staticflickr.com media.githubusercontent.com pbs.twimg.com platform.twitter.com s3.amazonaws.com stats.g.doubleclick.net syndication.twitter.com web.archive.org www.google-analytics.com www.google.com www.googletagmanager.com www.google.co.in; media-src 'self' blob: ryanparman.com cdn.ryanparman.com *.http.atlas.cdn.yimg.com s3.amazonaws.com www.flickr.com cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' ajax.cloudflare.com cdn.ryanparman.com cdn.jsdelivr.net cdn.syndication.twimg.com embedr.flickr.com gist.github.com platform.twitter.com widgets.flickr.com www.google-analytics.com www.googletagmanager.com www.instagram.com; script-src-elem 'unsafe-inline' cdn.ryanparman.com ajax.cloudflare.com www.googletagmanager.com www.google-analytics.com; style-src 'self' 'unsafe-inline' cdn.ryanparman.com github.githubassets.com platform.twitter.com; font-src 'self' data: cdn.ryanparman.com; style-src-attr 'unsafe-inline'; report-uri https://ryanparman.report-uri.com/r/d/csp/wizard; upgrade-insecure-requests; block-all-mixed-content
*/

// Copyright 2023-2024, Northwood Labs
// Copyright 2023-2024, Ryan Parman <rparman@northwood-labs.com>
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
	"testing"
)

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsBase64(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: true,
		},
		"rAnd0m": {
			Input:    "rAnd0m",
			Expected: true,
		},
		"xzi4zkCjuC8lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ=": {
			Input:    "xzi4zkCjuC8lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ=",
			Expected: true,
		},
		"nMxMqdZhkHxz5vAuW/PAoLvECzzsmeAxD/BNwG15HuA=": {
			Input:    "nMxMqdZhkHxz5vAuW/PAoLvECzzsmeAxD/BNwG15HuA=",
			Expected: true,
		},
		"5g0QXxO6NfvHJ6Uf5BK/hqQHtso8ZOdjlnbyKtYLvwc=": {
			Input:    "5g0QXxO6NfvHJ6Uf5BK/hqQHtso8ZOdjlnbyKtYLvwc=",
			Expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isBase64(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsASCII(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: true,
		},
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": {
			Input:    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			Expected: true,
		},
		"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~": {
			Input:    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			Expected: true,
		},
		"␡": {
			Input:    "␡",
			Expected: false,
		},
		"üüüüüü.de": {
			Input:    "üüüüüü.de",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isASCII(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}
