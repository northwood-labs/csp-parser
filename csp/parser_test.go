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

	"github.com/stretchr/testify/assert"
)

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
			assert := assert.New(t)
			actual := isSchemeSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
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
		"0.0.0.0": {
			Input:    "0.0.0.0",
			Expected: false,
		},
		"1.1.1.1": {
			Input:    "1.1.1.1",
			Expected: false,
		},
		"2.2.2.2": {
			Input:    "2.2.2.2",
			Expected: false,
		},
		"3.3.3.3": {
			Input:    "3.3.3.3",
			Expected: false,
		},
		"4.4.4.4": {
			Input:    "4.4.4.4",
			Expected: false,
		},
		"8.8.8.8": {
			Input:    "8.8.8.8",
			Expected: false,
		},
		"8.8.4.4": {
			Input:    "8.8.4.4",
			Expected: false,
		},
		"25.25.25.25": {
			Input:    "25.25.25.25",
			Expected: false,
		},
		"100.100.100.100": {
			Input:    "100.100.100.100",
			Expected: false,
		},
		"127.0.0.1": {
			Input:    "127.0.0.1",
			Expected: true,
		},
		"169.254.169.254": {
			Input:    "169.254.169.254",
			Expected: false,
		},
		"255.255.255.255": {
			Input:    "255.255.255.255",
			Expected: false,
		},
		"255.255.255.256": {
			Input:    "255.255.255.256",
			Expected: false,
		},
		"256.256.256.256": {
			Input:    "256.256.256.256",
			Expected: false,
		},
		"333.333.333.333": {
			Input:    "333.333.333.333",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isHostSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsValidIPv4(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"0.0.0.0": {
			Input:    "0.0.0.0",
			Expected: true,
		},
		"1.1.1.1": {
			Input:    "1.1.1.1",
			Expected: true,
		},
		"2.2.2.2": {
			Input:    "2.2.2.2",
			Expected: true,
		},
		"3.3.3.3": {
			Input:    "3.3.3.3",
			Expected: true,
		},
		"4.4.4.4": {
			Input:    "4.4.4.4",
			Expected: true,
		},
		"8.8.8.8": {
			Input:    "8.8.8.8",
			Expected: true,
		},
		"8.8.4.4": {
			Input:    "8.8.4.4",
			Expected: true,
		},
		"25.25.25.25": {
			Input:    "25.25.25.25",
			Expected: true,
		},
		"100.100.100.100": {
			Input:    "100.100.100.100",
			Expected: true,
		},
		"127.0.0.1": {
			Input:    "127.0.0.1",
			Expected: true,
		},
		"169.254.169.254": {
			Input:    "169.254.169.254",
			Expected: true,
		},
		"255.255.255.255": {
			Input:    "255.255.255.255",
			Expected: true,
		},
		"255.255.255.256": {
			Input:    "255.255.255.256",
			Expected: false,
		},
		"256.256.256.256": {
			Input:    "256.256.256.256",
			Expected: false,
		},
		"333.333.333.333": {
			Input:    "333.333.333.333",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isValidIPv4(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
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

		// Single quotes (pass)
		"'self'": {
			Input:    "'self'",
			Expected: true,
		},
		"'SeLF'": {
			Input:    "'SeLF'",
			Expected: true,
		},
		"'report-sample'": {
			Input:    "'report-sample'",
			Expected: true,
		},
		"'strict-dynamic'": {
			Input:    "'strict-dynamic'",
			Expected: true,
		},
		"'unsafe-allow-redirects'": {
			Input:    "'unsafe-allow-redirects'",
			Expected: true,
		},
		"'unsafe-eval'": {
			Input:    "'unsafe-eval'",
			Expected: true,
		},
		"'unsafe-hashes'": {
			Input:    "'unsafe-hashes'",
			Expected: true,
		},
		"'unsafe-inline'": {
			Input:    "'unsafe-inline'",
			Expected: true,
		},
		"'wasm-unsafe-eval'": {
			Input:    "'wasm-unsafe-eval'",
			Expected: true,
		},

		// Double quotes (fail)
		`"self"`: {
			Input:    `"self"`,
			Expected: false,
		},
		`"SeLF"`: {
			Input:    `"SeLF"`,
			Expected: false,
		},
		`"report-sample"`: {
			Input:    `"report-sample"`,
			Expected: false,
		},
		`"strict-dynamic"`: {
			Input:    `"strict-dynamic"`,
			Expected: false,
		},
		`"unsafe-allow-redirects"`: {
			Input:    `"unsafe-allow-redirects"`,
			Expected: false,
		},
		`"unsafe-eval"`: {
			Input:    `"unsafe-eval"`,
			Expected: false,
		},
		`"unsafe-hashes"`: {
			Input:    `"unsafe-hashes"`,
			Expected: false,
		},
		`"unsafe-inline"`: {
			Input:    `"unsafe-inline"`,
			Expected: false,
		},
		`"wasm-unsafe-eval"`: {
			Input:    `"wasm-unsafe-eval"`,
			Expected: false,
		},

		// No quotes (fail)
		"self": {
			Input:    "self",
			Expected: false,
		},
		"SeLF": {
			Input:    "SeLF",
			Expected: false,
		},
		"report-sample": {
			Input:    "report-sample",
			Expected: false,
		},
		"strict-dynamic": {
			Input:    "strict-dynamic",
			Expected: false,
		},
		"unsafe-allow-redirects": {
			Input:    "unsafe-allow-redirects",
			Expected: false,
		},
		"unsafe-eval": {
			Input:    "unsafe-eval",
			Expected: false,
		},
		"unsafe-hashes": {
			Input:    "unsafe-hashes",
			Expected: false,
		},
		"unsafe-inline": {
			Input:    "unsafe-inline",
			Expected: false,
		},
		"wasm-unsafe-eval": {
			Input:    "wasm-unsafe-eval",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isKeywordSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
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
		"'NONCE-R4ND0M'": {
			Input:    "'NONCE-R4ND0M'",
			Expected: true,
		},
		`"nonce-r4nd0m"`: {
			Input:    `"nonce-r4nd0m"`,
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isNonceSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
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
		"'SHA256-R4ND0M'": {
			Input:    "'SHA256-R4ND0M'",
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
			assert := assert.New(t)
			actual := isHashSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
// Grabbed a smattering of media types from the IANA list.
// https://www.iana.org/assignments/media-types/media-types.xhtml
func TestIsMediaType(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"application/3gppHalForms+json": {
			Input:    "application/3gppHalForms+json",
			Expected: true,
		},
		"application/AML": {
			Input:    "application/AML",
			Expected: true,
		},
		"application/atom+xml": {
			Input:    "application/atom+xml",
			Expected: true,
		},
		"application/calendar+xml": {
			Input:    "application/calendar+xml",
			Expected: true,
		},
		"application/conference-info+xml": {
			Input:    "application/conference-info+xml",
			Expected: true,
		},
		"application/EmergencyCallData.ServiceInfo+xml": {
			Input:    "application/EmergencyCallData.ServiceInfo+xml",
			Expected: true,
		},
		"application/json": {
			Input:    "application/json",
			Expected: true,
		},
		"APPLICATION/JSON": {
			Input:    "APPLICATION/JSON",
			Expected: true,
		},
		"application/mathml-content+xml": {
			Input:    "application/mathml-content+xml",
			Expected: true,
		},
		"application/pkcs12": {
			Input:    "application/pkcs12",
			Expected: true,
		},
		"application/TETRA_ISI": {
			Input:    "application/TETRA_ISI",
			Expected: true,
		},
		"application/vnd.3gpp.access-transfer-events+xml": {
			Input:    "application/vnd.3gpp.access-transfer-events+xml",
			Expected: true,
		},
		"application/vnd.cncf.helm.chart.content.v1.tar+gzip": {
			Input:    "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
			Expected: true,
		},
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {
			Input:    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml",
			Expected: true,
		},
		"audio/aac": {
			Input:    "audio/aac",
			Expected: true,
		},
		"audio/ATRAC-ADVANCED-LOSSLESS": {
			Input:    "audio/ATRAC-ADVANCED-LOSSLESS",
			Expected: true,
		},
		"audio/TETRA_ACELP": {
			Input:    "audio/TETRA_ACELP",
			Expected: true,
		},
		"image/avif": {
			Input:    "image/avif",
			Expected: true,
		},
		"image/svg+xml": {
			Input:    "image/svg+xml",
			Expected: true,
		},
		"image/vnd.adobe.photoshop": {
			Input:    "image/vnd.adobe.photoshop",
			Expected: true,
		},
		"image/vnd.mozilla.apng": {
			Input:    "image/vnd.mozilla.apng",
			Expected: true,
		},
		"message/CPIM": {
			Input:    "message/CPIM",
			Expected: true,
		},
		"message/delivery-status": {
			Input:    "message/delivery-status",
			Expected: true,
		},
		"message/imdn+xml": {
			Input:    "message/imdn+xml",
			Expected: true,
		},
		"message/vnd.wfa.wsc": {
			Input:    "message/vnd.wfa.wsc",
			Expected: true,
		},
		"model/obj": {
			Input:    "model/obj",
			Expected: true,
		},
		"model/step-xml+zip": {
			Input:    "model/step-xml+zip",
			Expected: true,
		},
		"model/x3d-vrml": {
			Input:    "model/x3d-vrml",
			Expected: true,
		},
		"multipart/form-data": {
			Input:    "multipart/form-data",
			Expected: true,
		},
		"text/css": {
			Input:    "text/css",
			Expected: true,
		},
		"text/markdown": {
			Input:    "text/markdown",
			Expected: true,
		},
		"text/rfc822-headers": {
			Input:    "text/rfc822-headers",
			Expected: true,
		},
		"text/vnd.graphviz": {
			Input:    "text/vnd.graphviz",
			Expected: true,
		},
		"video/AV1": {
			Input:    "video/AV1",
			Expected: true,
		},
		"video/iso.segment": {
			Input:    "video/iso.segment",
			Expected: true,
		},
		"video/mpeg4-generic": {
			Input:    "video/mpeg4-generic",
			Expected: true,
		},
		"video/vnd.CCTV": {
			Input:    "video/vnd.CCTV",
			Expected: true,
		},
		"video/vnd.iptvforum.2dparityfec-2005": {
			Input:    "video/vnd.iptvforum.2dparityfec-2005",
			Expected: true,
		},
		"txt/plain": {
			Input:    "txt/plain",
			Expected: false,
		},
		"img/png": {
			Input:    "img/png",
			Expected: false,
		},
		"application/*": {
			Input:    "application/*",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isMediaType(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsSandboxSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"allow-forms": {
			Input:    "allow-forms",
			Expected: true,
		},
		"allow-pointer-lock": {
			Input:    "allow-pointer-lock",
			Expected: true,
		},
		"allow-popups": {
			Input:    "allow-popups",
			Expected: true,
		},
		"allow-same-origin": {
			Input:    "allow-same-origin",
			Expected: true,
		},
		"allow-scripts": {
			Input:    "allow-scripts",
			Expected: true,
		},
		"allow-top-navigation": {
			Input:    "allow-top-navigation",
			Expected: true,
		},
		"ALLOW-FORMS": {
			Input:    "ALLOW-FORMS",
			Expected: true,
		},
		"ALLOW-POINTER-LOCK": {
			Input:    "ALLOW-POINTER-LOCK",
			Expected: true,
		},
		"ALLOW-POPUPS": {
			Input:    "ALLOW-POPUPS",
			Expected: true,
		},
		"ALLOW-SAME-ORIGIN": {
			Input:    "ALLOW-SAME-ORIGIN",
			Expected: true,
		},
		"ALLOW-SCRIPTS": {
			Input:    "ALLOW-SCRIPTS",
			Expected: true,
		},
		"ALLOW-TOP-NAVIGATION": {
			Input:    "ALLOW-TOP-NAVIGATION",
			Expected: true,
		},
		"allowForms": {
			Input:    "allowForms",
			Expected: false,
		},
		"allowPointerLock": {
			Input:    "allowPointerLock",
			Expected: false,
		},
		"allowPopups": {
			Input:    "allowPopups",
			Expected: false,
		},
		"allowSameOrigin": {
			Input:    "allowSameOrigin",
			Expected: false,
		},
		"allowScripts": {
			Input:    "allowScripts",
			Expected: false,
		},
		"allowTopNavigation": {
			Input:    "allowTopNavigation",
			Expected: false,
		},
		"AllowForms": {
			Input:    "AllowForms",
			Expected: false,
		},
		"AllowPointerLock": {
			Input:    "AllowPointerLock",
			Expected: false,
		},
		"AllowPopups": {
			Input:    "AllowPopups",
			Expected: false,
		},
		"AllowSameOrigin": {
			Input:    "AllowSameOrigin",
			Expected: false,
		},
		"AllowScripts": {
			Input:    "AllowScripts",
			Expected: false,
		},
		"AllowTopNavigation": {
			Input:    "AllowTopNavigation",
			Expected: false,
		},
		"allow_forms": {
			Input:    "allow_forms",
			Expected: false,
		},
		"allow_pointer_lock": {
			Input:    "allow_pointer_lock",
			Expected: false,
		},
		"allow_popups": {
			Input:    "allow_popups",
			Expected: false,
		},
		"allow_same_origin": {
			Input:    "allow_same_origin",
			Expected: false,
		},
		"allow_scripts": {
			Input:    "allow_scripts",
			Expected: false,
		},
		"allow_top_navigation": {
			Input:    "allow_top_navigation",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isSandboxSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsValidReportingURL(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},
		"www.google-analytics.com": {
			Input:    "www.google-analytics.com",
			Expected: false,
		},
		"static.cloudflareinsights.com": {
			Input:    "static.cloudflareinsights.com",
			Expected: false,
		},
		"*.static.flickr.com": {
			Input:    "*.static.flickr.com",
			Expected: false,
		},
		"https://ryanparman.report-uri.com/r/d/csp/wizard": {
			Input:    "https://ryanparman.report-uri.com/r/d/csp/wizard",
			Expected: true,
		},
		"https://ryanparman.report-uri.com/r/d/csp/wizard#fail": {
			Input:    "https://ryanparman.report-uri.com/r/d/csp/wizard#fail",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isValidReportingURL(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}

// <https://github.com/golang/go/wiki/TableDrivenTests>
func TestIsWebRTCSource(t *testing.T) {
	for name, tc := range map[string]struct {
		Input    string
		Expected bool
	}{
		"blank": {
			Input:    "",
			Expected: false,
		},

		// Single quotes (pass)
		"'allow'": {
			Input:    "'allow'",
			Expected: true,
		},
		"'ALLoW'": {
			Input:    "'ALLoW'",
			Expected: true,
		},
		"'block'": {
			Input:    "'block'",
			Expected: true,
		},
		"'blocked'": {
			Input:    "'blocked'",
			Expected: false,
		},

		// Double quotes (fail)
		`"allow"`: {
			Input:    `"allow"`,
			Expected: false,
		},
		`"ALLoW"`: {
			Input:    `"ALLoW"`,
			Expected: false,
		},
		`"block"`: {
			Input:    `"block"`,
			Expected: false,
		},
		`"blocked"`: {
			Input:    `"blocked"`,
			Expected: false,
		},

		// No quotes (fail)
		"allow": {
			Input:    "allow",
			Expected: false,
		},
		"ALLoW": {
			Input:    "ALLoW",
			Expected: false,
		},
		"block": {
			Input:    "block",
			Expected: false,
		},
		"blocked": {
			Input:    "blocked",
			Expected: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			actual := isWebRTCSource(tc.Input)

			assert.Equalf(tc.Expected, actual, "Expected `%v`, but got `%v`.", tc.Expected, actual)
		})
	}
}
