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
			Expected: false,
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
func TestIsAlphaDigit(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": {
			Input:    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			Expected: true,
		},
		"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~": {
			Input:    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			Expected: false,
		},
		"␡": {
			Input:    "␡",
			Expected: false,
		},
		"üüüüüü.de": {
			Input:    "üüüüüü.de",
			Expected: false,
		},
		"$＄": {
			Input:    "$＄",
			Expected: false,
		},
		"%％": {
			Input:    "%％",
			Expected: false,
		},
		";;": {
			Input:    ";;",
			Expected: false,
		},
		"@＠": {
			Input:    "@＠",
			Expected: false,
		},
		"£₤": {
			Input:    "£₤",
			Expected: false,
		},
		"£": {
			Input:    "£",
			Expected: false,
		},
		"ᘮᘴ": {
			Input:    "ᘮᘴ",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isAlphaDigit(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsSchemeSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"http:": {
			Input:    "http:",
			Expected: true,
		},
		"https:": {
			Input:    "https:",
			Expected: true,
		},
		"mailto:": {
			Input:    "mailto:",
			Expected: true,
		},
		"feed:": {
			Input:    "feed:",
			Expected: true,
		},
		"rss:": {
			Input:    "rss:",
			Expected: true,
		},
		"s3:": {
			Input:    "s3:",
			Expected: true,
		},
		"webcal:": {
			Input:    "webcal:",
			Expected: true,
		},
		"webcal": {
			Input:    "webcal",
			Expected: false,
		},
		"apple-otpauth:": {
			Input:    "apple-otpauth:",
			Expected: true,
		},
		"cloudkit-icloud.com.dayoneapp:": {
			Input:    "cloudkit-icloud.com.dayoneapp:",
			Expected: true,
		},
		"x-man-page:": {
			Input:    "x-man-page:",
			Expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isSchemeSource(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsHostSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"https://example.com": {
			Input:    "https://example.com",
			Expected: true,
		},
		"https://example.com/": {
			Input:    "https://example.com/",
			Expected: false,
		},
		"https://example.com./": {
			Input:    "https://example.com./",
			Expected: false,
		},
		"x-man-page:find": {
			Input:    "x-man-page:find",
			Expected: false,
		},
		"www.google-analytics.com": {
			Input:    "www.google-analytics.com",
			Expected: true,
		},
		"ajax.googleapis.com": {
			Input:    "ajax.googleapis.com",
			Expected: true,
		},
		"js-cdn.example.com": {
			Input:    "js-cdn.example.com",
			Expected: true,
		},
		"css-cdn.example.com": {
			Input:    "css-cdn.example.com",
			Expected: true,
		},
		"https://images.example.com": {
			Input:    "https://images.example.com",
			Expected: true,
		},
		"static.cloudflareinsights.com": {
			Input:    "static.cloudflareinsights.com",
			Expected: true,
		},
		"www.googletagmanager.com/gtag/js": {
			Input:    "www.googletagmanager.com/gtag/js",
			Expected: true,
		},
		"*.http.atlas.cdn.yimg.com": {
			Input:    "*.http.atlas.cdn.yimg.com",
			Expected: true,
		},
		"*.static.flickr.com": {
			Input:    "*.static.flickr.com",
			Expected: true,
		},
		"*.staticflickr.com": {
			Input:    "*.staticflickr.com",
			Expected: true,
		},
		"ajax.cloudflare.com": {
			Input:    "ajax.cloudflare.com",
			Expected: true,
		},
		"cdn.jsdelivr.net": {
			Input:    "cdn.jsdelivr.net",
			Expected: true,
		},
		"cdn.ryanparman.com": {
			Input:    "cdn.ryanparman.com",
			Expected: true,
		},
		"cdn.syndication.twimg.com": {
			Input:    "cdn.syndication.twimg.com",
			Expected: true,
		},
		"embed.music.apple.com": {
			Input:    "embed.music.apple.com",
			Expected: true,
		},
		"embedr.flickr.com": {
			Input:    "embedr.flickr.com",
			Expected: true,
		},
		"gist.github.com": {
			Input:    "gist.github.com",
			Expected: true,
		},
		"github.githubassets.com": {
			Input:    "github.githubassets.com",
			Expected: true,
		},
		"media.githubusercontent.com": {
			Input:    "media.githubusercontent.com",
			Expected: true,
		},
		"pbs.twimg.com": {
			Input:    "pbs.twimg.com",
			Expected: true,
		},
		"platform.twitter.com": {
			Input:    "platform.twitter.com",
			Expected: true,
		},
		"ryanparman.com": {
			Input:    "ryanparman.com",
			Expected: true,
		},
		"s3.amazonaws.com": {
			Input:    "s3.amazonaws.com",
			Expected: true,
		},
		"stats.g.doubleclick.net": {
			Input:    "stats.g.doubleclick.net",
			Expected: true,
		},
		"syndication.twitter.com": {
			Input:    "syndication.twitter.com",
			Expected: true,
		},
		"web.archive.org": {
			Input:    "web.archive.org",
			Expected: true,
		},
		"widgets.flickr.com": {
			Input:    "widgets.flickr.com",
			Expected: true,
		},
		"www.flickr.com": {
			Input:    "www.flickr.com",
			Expected: true,
		},
		"www.google.co.in": {
			Input:    "www.google.co.in",
			Expected: true,
		},
		"www.google.com": {
			Input:    "www.google.com",
			Expected: true,
		},
		"www.googletagmanager.com": {
			Input:    "www.googletagmanager.com",
			Expected: true,
		},
		"www.instagram.com": {
			Input:    "www.instagram.com",
			Expected: true,
		},
		"www.youtube.com": {
			Input:    "www.youtube.com",
			Expected: true,
		},
		"yourmomü.com": {
			Input:    "yourmomü.com",
			Expected: false,
		},
		"ουτοπία.δπθ.gr": {
			Input:    "ουτοπία.δπθ.gr",
			Expected: false,
		},
		"xn--kxae4bafwg.xn--pxaix.gr": {
			Input:    "xn--kxae4bafwg.xn--pxaix.gr",
			Expected: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isHostSource(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsKeywordSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"'self'": {
			Input:    "'self'",
			Expected: true,
		},
		"'unsafe-inline'": {
			Input:    "'unsafe-inline'",
			Expected: true,
		},
		"'unsafe-eval'": {
			Input:    "'unsafe-eval'",
			Expected: true,
		},
		`"self"`: {
			Input:    `"self"`,
			Expected: false,
		},
		`"unsafe-inline"`: {
			Input:    `"unsafe-inline"`,
			Expected: false,
		},
		`"unsafe-eval"`: {
			Input:    `"unsafe-eval"`,
			Expected: false,
		},
		"self": {
			Input:    "self",
			Expected: false,
		},
		"unsafe-inline": {
			Input:    "unsafe-inline",
			Expected: false,
		},
		"unsafe-eval": {
			Input:    "unsafe-eval",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isKeywordSource(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsNonceSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"nonce": {
			Input:    "nonce",
			Expected: false,
		},
		"'nonce'": {
			Input:    "'nonce'",
			Expected: false,
		},
		`"nonce"`: {
			Input:    `"nonce"`,
			Expected: false,
		},
		"nonce-": {
			Input:    "nonce-",
			Expected: false,
		},
		"'nonce-'": {
			Input:    "'nonce-'",
			Expected: false,
		},
		`"nonce-"`: {
			Input:    `"nonce-"`,
			Expected: false,
		},
		"nonce-r4nd0m": {
			Input:    "nonce-r4nd0m",
			Expected: false,
		},
		"'nonce-r4nd0m'": {
			Input:    "'nonce-r4nd0m'",
			Expected: true,
		},
		`"nonce-r4nd0m"`: {
			Input:    `"nonce-r4nd0m"`,
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isNonceSource(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsHashSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"sha256": {
			Input:    "sha256",
			Expected: false,
		},
		"'sha256'": {
			Input:    "'sha256'",
			Expected: false,
		},
		`"sha256"`: {
			Input:    `"sha256"`,
			Expected: false,
		},
		"sha256-": {
			Input:    "sha256-",
			Expected: false,
		},
		"'sha256-'": {
			Input:    "'sha256-'",
			Expected: false,
		},
		`"sha256-"`: {
			Input:    `"sha256-"`,
			Expected: false,
		},
		"sha256-r4nd0m": {
			Input:    "sha256-r4nd0m",
			Expected: false,
		},
		"'sha256-r4nd0m'": {
			Input:    "'sha256-r4nd0m'",
			Expected: true,
		},
		`"sha256-r4nd0m"`: {
			Input:    `"sha256-r4nd0m"`,
			Expected: false,
		},
		"sha384": {
			Input:    "sha384",
			Expected: false,
		},
		"'sha384'": {
			Input:    "'sha384'",
			Expected: false,
		},
		`"sha384"`: {
			Input:    `"sha384"`,
			Expected: false,
		},
		"sha384-": {
			Input:    "sha384-",
			Expected: false,
		},
		"'sha384-'": {
			Input:    "'sha384-'",
			Expected: false,
		},
		`"sha384-"`: {
			Input:    `"sha384-"`,
			Expected: false,
		},
		"sha384-r4nd0m": {
			Input:    "sha384-r4nd0m",
			Expected: false,
		},
		"'sha384-r4nd0m'": {
			Input:    "'sha384-r4nd0m'",
			Expected: true,
		},
		`"sha384-r4nd0m"`: {
			Input:    `"sha384-r4nd0m"`,
			Expected: false,
		},
		"sha512": {
			Input:    "sha512",
			Expected: false,
		},
		"'sha512'": {
			Input:    "'sha512'",
			Expected: false,
		},
		`"sha512"`: {
			Input:    `"sha512"`,
			Expected: false,
		},
		"sha512-": {
			Input:    "sha512-",
			Expected: false,
		},
		"'sha512-'": {
			Input:    "'sha512-'",
			Expected: false,
		},
		`"sha512-"`: {
			Input:    `"sha512-"`,
			Expected: false,
		},
		"sha512-r4nd0m": {
			Input:    "sha512-r4nd0m",
			Expected: false,
		},
		"'sha512-r4nd0m'": {
			Input:    "'sha512-r4nd0m'",
			Expected: true,
		},
		`"sha512-r4nd0m"`: {
			Input:    `"sha512-r4nd0m"`,
			Expected: false,
		},
		"'sha128-r4nd0m'": {
			Input:    "'sha128-r4nd0m'",
			Expected: false,
		},
		"'sha1-r4nd0m'": {
			Input:    "'sha1-r4nd0m'",
			Expected: false,
		},
		"'sha2-r4nd0m'": {
			Input:    "'sha2-r4nd0m'",
			Expected: false,
		},
		"'sha3-r4nd0m'": {
			Input:    "'sha3-r4nd0m'",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			actual := isHashSource(tc.Input)

			if actual != tc.Expected {
				t.Errorf("Expected `%v`, but got `%v`.", tc.Expected, actual)
			}
		})
	}
}

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
default-src 'self';font-src fonts.gstatic.com;style-src 'self' fonts.googleapis.com;style-src 'self' yourmom.com
script-src maps.googleapis.com;img-src data: maps.gstatic.com *.googleapis.com *.ggpht.com
script-src 'self' platform.twitter.com syndication.twitter.com; style-src 'self' 'sha256-5g0QXxO6NfvHJ6Uf5BK/hqQHtso8ZOdjlnbyKtYLvwc='; frame-src 'self' platform.twitter.com

https://content-security-policy.com/examples/multiple-csp-headers/

default-src 'self' blob: cdn.ryanparman.com; connect-src 'self' cdn.ryanparman.com embedr.flickr.com; frame-src cdn.ryanparman.com embed.music.apple.com platform.twitter.com syndication.twitter.com www.google.com www.instagram.com www.youtube.com; img-src 'self' 'unsafe-inline' data: cdn.ryanparman.com *.static.flickr.com *.staticflickr.com media.githubusercontent.com pbs.twimg.com platform.twitter.com s3.amazonaws.com stats.g.doubleclick.net syndication.twitter.com web.archive.org www.google-analytics.com www.google.com www.googletagmanager.com www.google.co.in; media-src 'self' blob: ryanparman.com cdn.ryanparman.com *.http.atlas.cdn.yimg.com s3.amazonaws.com www.flickr.com cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' ajax.cloudflare.com cdn.ryanparman.com cdn.jsdelivr.net cdn.syndication.twimg.com embedr.flickr.com gist.github.com platform.twitter.com widgets.flickr.com www.google-analytics.com www.googletagmanager.com www.instagram.com; script-src-elem 'unsafe-inline' cdn.ryanparman.com ajax.cloudflare.com www.googletagmanager.com www.google-analytics.com; style-src 'self' 'unsafe-inline' cdn.ryanparman.com github.githubassets.com platform.twitter.com; font-src 'self' data: cdn.ryanparman.com; style-src-attr 'unsafe-inline'; report-uri https://ryanparman.report-uri.com/r/d/csp/wizard; upgrade-insecure-requests; block-all-mixed-content
*/