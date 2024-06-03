# CSP Parser and Evaluator in Go

The goal of this project is to be able to take a URL and one or more CSP headers, understand them correctly, and ultimately be able to provide education and actionable feedback for ensuring CSP provide the appropriate and intended level of security. This is the underlying library intended to make that ultimate goal possible.

This code is not a web browser, so the parts of the spec about "blocking networking requests" aren't relevant. However, calling this out as what a web browser _would do_ can be helpful.

> [!CAUTION]
> Partially working. Code which parses the policy has complete support for CSP Level 2, and CSP Level 3 (Draft) support is mostly complete. Code which performs deeper evaluation of the content of the page against the CSP policy has not yet been started.

Implements parsing and evaluation for [CSP2](https://www.w3.org/TR/CSP2/) (2016) and the [CSP3 working draft](https://www.w3.org/TR/2024/WD-CSP3-20240424/) (April 2024).

## Call-outs from the CSP specs

| Directive                       | Notes for implementors                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [base-uri]                      | <p>The `base-uri` directive restricts the URLs that can be used to specify the document base URL.</p>                                                                                                                                                                                                                                                                                                                                                                          |
| [block-all-mixed-content] (e)   | <p>An _extension_ to CSP; The `block-all-mixed-content` directive disallows any `http:` resources from being used with `https:`-served websites.</p>                                                                                                                                                                                                                                                                                                                           |
| [child-src]                     | <p>The `child-src` directive governs the creation of nested browsing contexts (e.g., frames) as well as `Worker` execution contexts.</p>                                                                                                                                                                                                                                                                                                                                       |
| [connect-src]                   | <p>The `connect-src` directive restricts which URLs the protected resource can load using script interfaces.</p><p>Affects: processing [XMLHttpRequest.send()]; [WebSocket]; [EventSource]; Pinging during [hyperlink auditing]; the [navigator.sendBeacon()] method.</p>                                                                                                                                                                                                      |
| [default-src]                   | <p>The `default-src` directive sets a default source list for a number of directives.</p>                                                                                                                                                                                                                                                                                                                                                                                      |
| [font-src]                      | <p>The `font-src` directive restricts from where the protected resource can load fonts.</p><p>Affects: the `@font-face` CSS rule.</p>                                                                                                                                                                                                                                                                                                                                          |
| [form-action]                   | <p>The `form-action` restricts which URLs can be used as the action of HTML form elements.</p>                                                                                                                                                                                                                                                                                                                                                                                 |
| [frame-ancestors]               | <p>The `frame-ancestors` directive restricts embedding the resource using a `frame`, `iframe`, `object`, `embed`, or `applet` element, or equivalent functionality in non-HTML resources.</p><p>Resources can use this directive to avoid many [UI Redressing attacks] by avoiding being embedded into potentially hostile contexts. The `frame-ancestors` directive obsoletes the [X-Frame-Options] header.</p>                                                               |
| [frame-src]                     | <p>The `frame-src` directive restricts the URLs which may be loaded into child _navigables_.</p>                                                                                                                                                                                                                                                                                                                                                                               |
| [img-src]                       | <p>The `img-src` directive restricts from where the protected resource can load images.</p><p>Affects: the `src` or `srcset` attributes of an [img] element; the `src` attribute of an [input] element with a type of `image`, the `poster` attribute of a [video] element, the [url()], [image()], or [image-set()] values on any CSS property; or the `href` attribute of a [link] element with an image-related `rel` attribute, such as `icon`.</p>                        |
| [manifest-src]                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| [media-src]                     | <p>The `media-src` directive restricts from where the protected resource can load video, audio, and associated text tracks.</p><p>Affects: data for a video or audio clip, such as when processing the `src` attribute of a [video], [audio], [source], or [track] element.</p>                                                                                                                                                                                                |
| [object-src]                    | <p>The `object-src` directive restricts from where the protected resource can load plugins.</p><p>Affects: data for a plugin, such as when processing the `data` attribute of an [object] element, the `src` attribute of an [embed] element, or the `code` or `archive` attributes of an [applet] element; requesting data for display in a nested browsing context in the protected resource created by an [object] or an [embed] element.</p>                               |
| [plugin-types]                  | <p>The `plugin-types` directive restricts the set of plugins that can be invoked by the protected resource by limiting the types of resources that can be embedded.</p>                                                                                                                                                                                                                                                                                                        |
| [report-to]                     | <p>The `report-to` directive specifies an identifier defined in the `Reporting-Endpoints` HTTP response header field to which to send reports. See [Reporting API] for more information.</p>                                                                                                                                                                                                                                                                                   |
| [report-uri]                    | <p>The `report-uri` directive specifies a URL to which the user agent sends reports about policy violation.</p><p>Deprecated, but will require transition time. Use this along with `report-to` in the interim.</p>                                                                                                                                                                                                                                                            |
| [sandbox]                       | <p>The `sandbox` directive specifies an HTML sandbox policy that the user agent applies to the protected resource. The set of flags available to the CSP directive should match those available to the [iframe] attribute.</p>                                                                                                                                                                                                                                                 |
| [script-src-attr]               | <p>The `script-src-attr` directive applies to event handlers and, if present, it will override the `script-src` directive for relevant checks.</p>                                                                                                                                                                                                                                                                                                                             |
| [script-src-elem]               | <p>The `script-src-elem` directive applies to all script requests and script blocks. Attributes that execute script (inline event handlers) are controlled via `script-src-attr`.</p>                                                                                                                                                                                                                                                                                          |
| [script-src]                    | <p>The `script-src` directive restricts which scripts the protected resource can execute. The directive also controls other resources, such as [XSLT style sheets], which can cause the user agent to execute script.</p><p>`unsafe-inline` SHOULD be avoided in favor of [nonce-source] or [hash-source]. `unsafe-eval` SHOULD be avoided in favor of passing _callables_ (instead of _strings_) to [setTimeout()], [setInterval()], `setImmediate()`, or `execScript()`.</p> |
| [style-src-attr]                | <p>The `style-src-attr` directive governs the behaviour of style attributes.</p>                                                                                                                                                                                                                                                                                                                                                                                               |
| [style-src-elem]                | <p>The `style-src-elem` directive governs the behaviour of styles except for styles defined in inline attributes.</p>                                                                                                                                                                                                                                                                                                                                                          |
| [style-src]                     | <p>The `style-src` directive restricts which styles the user may applies to the protected resource.</p><p>`unsafe-inline` SHOULD be avoided in favor of [nonce-source] or [hash-source]. Affects: the `href` of a [link] element where `rel=stylesheet`; the `@import` directive; a [`Link` HTTP response header] field.</p>                                                                                                                                                   |
| [upgrade-insecure-requests] (e) | <p>An _extension_ to CSP; The `upgrade-insecure-requests` directive instructs the browser to load any `http:` resources over `https:` instead.</p>                                                                                                                                                                                                                                                                                                                             |
| [webrtc]                        | <p>The `webrtc` directive determines whether or not _any_ WebRTC connectivity is allowed.</p>                                                                                                                                                                                                                                                                                                                                                                                  |
| [worker-src]                    |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

### Fallbacks

When the child nodes are undefined, their values will fall back to their parent's definition. Nodes at the root (all the way to the left) have no fallback.

Processing is right-to-left, and resolving the value of [worker-src] works _slightly_ differently from resolving the value of [frame-src].

<details>
<summary>See tree…</summary><br>

* [base-uri]
* [block-all-mixed-content] — Extension has no value; treat as boolean.
* [default-src]
  * [child-src]
    * [frame-src]
  * [connect-src]
  * [font-src]
  * [img-src]
  * [media-src]
  * [object-src]
  * [script-src]
    * [child-src]
      * [worker-src]
    * [script-src-attr]
    * [script-src-elem]
  * [style-src]
    * [style-src-attr]
    * [style-src-elem]
* [form-action]
* [frame-ancestors]
* [manifest-src]
* [plugin-types]
* [report-uri] — Deprecated.
  * [report-to]
* [sandbox]
* [upgrade-insecure-requests] — Extension has no value; treat as boolean.
* [webrtc]

</details>

## References

* [Content Security Policy Level 2](https://www.w3.org/TR/CSP2/) (formal recommendation)
* [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) (working draft)
* [web.dev: Content security policy](https://web.dev/articles/csp)
* [MDN: Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
* [OWASP: Content security policy](https://owasp.org/www-community/controls/Content_Security_Policy)
* [content-security-policy.com](https://content-security-policy.com)
* [Can I use: Content Security Policy?](https://caniuse.com/?search=Content%20Security%20Policy)
* [Mozilla HTTP Observatory](https://github.com/mozilla/http-observatory)
* [csp-evaluator](https://csp-evaluator.withgoogle.com)

[base-uri]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-base-uri
[block-all-mixed-content]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#biblio-mix
[child-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-child-src
[connect-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-connect-src
[default-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-default-src
[font-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-font-src
[form-action]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-form-action
[frame-ancestors]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-frame-ancestors
[frame-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-frame-src
[img-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-img-src
[manifest-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-manifest-src
[media-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-media-src
[object-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-object-src
[plugin-types]: https://www.w3.org/TR/CSP2/#directive-plugin-types
[report-to]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-report-to
[report-uri]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-report-uri
[sandbox]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-sandbox
[script-src-attr]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-script-src-attr
[script-src-elem]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-script-src-elem
[script-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-script-src
[style-src-attr]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-style-src-attr
[style-src-elem]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-style-src-elem
[style-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-style-src
[upgrade-insecure-requests]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#biblio-upgrade-insecure-requests
[webrtc]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-webrtc
[worker-src]: https://www.w3.org/TR/2024/WD-CSP3-20240424/#directive-worker-src

[`Link` HTTP response header]: https://datatracker.ietf.org/doc/html/rfc5988
[applet]: https://html.spec.whatwg.org/multipage/obsolete.html#non-conforming-features
[audio]: https://html.spec.whatwg.org/multipage/media.html#the-audio-element
[embed]: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-embed-element
[EventSource]: https://html.spec.whatwg.org/multipage/server-sent-events.html
[hash-source]: https://www.w3.org/TR/CSP2/#script-src-hash-usage
[hyperlink auditing]: https://html.spec.whatwg.org/multipage/links.html#hyperlink-auditing
[iframe]: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-element
[image-set()]: https://www.w3.org/TR/css-images-4/#image-set-notation
[image()]: https://drafts.csswg.org/css-values-3/#images
[img]: https://html.spec.whatwg.org/multipage/embedded-content.html#the-img-element
[input]: https://html.spec.whatwg.org/multipage/input.html#the-input-element
[link]: https://html.spec.whatwg.org/multipage/semantics.html#the-link-element
[navigator.sendBeacon()]: https://www.w3.org/TR/beacon/#sendbeacon-method
[nonce-source]: https://www.w3.org/TR/CSP2/#script-src-nonce-usage
[object]: https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-object-element
[Reporting API]: https://w3c.github.io/reporting/
[setInterval()]: https://html.spec.whatwg.org/multipage/timers-and-user-prompts.html#timers
[setTimeout()]: https://html.spec.whatwg.org/multipage/timers-and-user-prompts.html#timers
[source]: https://html.spec.whatwg.org/multipage/embedded-content.html#the-source-element
[track]: https://html.spec.whatwg.org/multipage/media.html#the-track-element
[UI Redressing attacks]: https://www.w3.org/TR/UISecurity/
[url()]: https://drafts.csswg.org/css-values-3/#url
[video]: https://html.spec.whatwg.org/multipage/media.html#the-video-element
[WebSocket]: https://websockets.spec.whatwg.org
[X-Frame-Options]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
[XMLHttpRequest.send()]: https://xhr.spec.whatwg.org/#the-send()-method
[XSLT style sheets]: https://www.w3.org/TR/xslt/
