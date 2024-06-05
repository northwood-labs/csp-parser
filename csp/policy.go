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

type (
	// source-list = *WSP [ source-expression *( 1*WSP source-expression ) *WSP ]
	//             / *WSP "'none'" *WSP
	//
	// https://www.w3.org/TR/CSP2/#source-list-syntax
	Policy struct {
		Info                 map[string]Info          `json:"info,omitempty"`
		WebRTC               WebRTCToken              `json:"webrtc,omitempty"`
		ChildSource          []SourceListItem         `json:"child-src,omitempty"`
		ConnectSource        []SourceListItem         `json:"connect-src,omitempty"`
		DefaultSource        []SourceListItem         `json:"default-src,omitempty"`
		FontSource           []SourceListItem         `json:"font-src,omitempty"`
		FormAction           []SourceListItem         `json:"form-action,omitempty"`
		FrameSource          []SourceListItem         `json:"frame-src,omitempty"`
		ImageSource          []SourceListItem         `json:"img-src,omitempty"`
		ManifestSource       []SourceListItem         `json:"manifest-src,omitempty"`
		MediaSource          []SourceListItem         `json:"media-src,omitempty"`
		ObjectSource         []SourceListItem         `json:"object-src,omitempty"`
		ScriptSource         []SourceListItem         `json:"script-src,omitempty"`
		ScriptSourceAttr     []SourceListItem         `json:"script-src-attr,omitempty"`
		ScriptSourceElem     []SourceListItem         `json:"script-src-elem,omitempty"`
		StyleSource          []SourceListItem         `json:"style-src,omitempty"`
		StyleSourceAttr      []SourceListItem         `json:"style-src-attr,omitempty"`
		StyleSourceElem      []SourceListItem         `json:"style-src-elem,omitempty"`
		WorkerSource         []SourceListItem         `json:"worker-src,omitempty"`
		FrameAncestors       []AncestorSourceListItem `json:"frame-ancestors,omitempty"`
		PluginTypes          []MediaTypeListItem      `json:"plugin-types,omitempty"`
		ReportTo             []ReportingRef           `json:"report-to,omitempty"`
		ReportURI            []URLRef                 `json:"report-uri,omitempty"`
		Sandbox              []SandboxToken           `json:"sandbox,omitempty"`
		BaseURI              []SourceListItem         `json:"base-uri,omitempty"`
		BlockAllMixedContent bool                     `json:"block-all-mixed-content,omitempty"`
		UpgradeInsecureReq   bool                     `json:"upgrade-insecure-requests,omitempty"`
	}

	Info struct {
		Description string   `json:"description,omitempty"`
		URL         string   `json:"url,omitempty"`
		Notes       []string `json:"notes,omitempty"`
	}

	SourceListItem struct {
		SourceExprs []SourceExpr `json:"sourceList,omitempty"`
	}

	// source-expression = scheme-source / host-source / keyword-source / nonce-source / hash-source / 'none'
	SourceExpr struct {
		SchemeSource  string `json:"schemeSource,omitempty"`
		HostSource    string `json:"hostSource,omitempty"`
		KeywordSource string `json:"keywordSource,omitempty"`
		NonceSource   string `json:"nonceSource,omitempty"`
		HashSource    string `json:"hashSource,omitempty"`
		None          bool   `json:"none,omitempty"`
	}

	// https://www.w3.org/TR/CSP2/#directive-frame-ancestors
	AncestorSourceListItem struct {
		AncestorExprs []AncestorExpr `json:"ancestorList,omitempty"`
	}

	// ancestor-source-list = [ ancestor-source *( 1*WSP ancestor-source ) ] / "'none'"
	// ancestor-source      = scheme-source / host-source
	AncestorExpr struct {
		SchemeSource string `json:"schemeSource,omitempty"`
		HostSource   string `json:"hostSource,omitempty"`
		None         bool   `json:"none,omitempty"`
	}

	// media-type-list   = media-type *( 1*WSP media-type )
	// media-type        = <type from RFC 2045> "/" <subtype from RFC 2045>
	// https://www.w3.org/TR/CSP2/#media-type-list-syntax
	MediaTypeListItem struct {
		MediaTypes []string `json:"mediaTypes,omitempty"`
	}

	// directive-name  = "sandbox"
	// directive-value = "" / sandbox-token *( 1*WSP sandbox-token )
	// sandbox-token   = <token from RFC 7230>
	SandboxToken struct {
		Allow []string `json:"allow,omitempty"`
	}

	// uri-reference = <URI-reference from RFC 3986>
	// https://datatracker.ietf.org/doc/html/rfc3986
	// https://url.spec.whatwg.org/commit-snapshots/eee49fdf4f99d59f717cbeb0bce29fda930196d4/
	URLRef struct {
		URLs []string `json:"urls,omitempty"`
	}

	ReportingRef struct {
		Tokens map[string]string `json:"tokens,omitempty"`
	}

	// directive-name  = "webrtc"
	// directive-value = "'allow'" / "'block'"
	WebRTCToken struct {
		Value string `json:"value,omitempty"`
	}
)
