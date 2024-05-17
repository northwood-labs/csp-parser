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
		Info map[string]Info `json:"info,omitempty"`

		BaseURI        []SourceListItem         `json:"base-uri,omitempty"`
		ChildSource    []SourceListItem         `json:"child-src,omitempty"`
		ConnectSource  []SourceListItem         `json:"connect-src,omitempty"`
		DefaultSource  []SourceListItem         `json:"default-src,omitempty"`
		FontSource     []SourceListItem         `json:"font-src,omitempty"`
		FormAction     []SourceListItem         `json:"form-action,omitempty"`
		FrameSource    []SourceListItem         `json:"frame-src,omitempty"`
		ImageSource    []SourceListItem         `json:"img-src,omitempty"`
		MediaSource    []SourceListItem         `json:"media-src,omitempty"`
		ObjectSource   []SourceListItem         `json:"object-src,omitempty"`
		ScriptSource   []SourceListItem         `json:"script-src,omitempty"`
		StyleSource    []SourceListItem         `json:"style-src,omitempty"`
		FrameAncestors []AncestorSourceListItem `json:"frame-ancestors,omitempty"`
		PluginTypes    []MediaTypeListItem      `json:"plugin-types,omitempty"`
		ReportURI      []URIReference           `json:"report-uri,omitempty"`
		Sandbox        []SandboxToken           `json:"sandbox,omitempty"`
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
		// 'none'
		None bool `json:"none,omitempty"`

		// scheme-source = scheme-part ":"
		// isSchemeSource()
		SchemeSource string `json:"schemeSource,omitempty"`

		// host-source = [ scheme-part "://" ] host-part [ port-part ] [ path-part ]
		// isHostSource()
		HostSource string `json:"hostSource,omitempty"`

		// keyword-source = "'self'" / "'unsafe-inline'" / "'unsafe-eval'"
		// isKeywordSource()
		KeywordSource string `json:"keywordSource,omitempty"`

		// nonce-value  = base64-value
		// nonce-source = "'nonce-" nonce-value "'"
		// isNonceSource()
		NonceSource string `json:"nonceSource,omitempty"`

		// hash-value  = base64-value
		// hash-algo   = "sha256" / "sha384" / "sha512"
		// hash-source = "'" hash-algo "-" hash-value "'"
		// isHashSource()
		HashSource string `json:"hashSource,omitempty"`
	}

	// https://www.w3.org/TR/CSP2/#directive-frame-ancestors
	AncestorSourceListItem struct{}

	// media-type-list   = media-type *( 1*WSP media-type )
	// media-type        = <type from RFC 2045> "/" <subtype from RFC 2045>
	// https://www.w3.org/TR/CSP2/#media-type-list-syntax
	MediaTypeListItem struct{}

	SandboxToken struct{}
	URIReference struct{}
)
