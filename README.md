# CSP Parser and Evaluator in Go

The goal of this project is to be able to take a URL and one or more CSP headers, understand them correctly, and ultimately be able to provide education and actionable feedback for ensuring CSP provide the appropriate and intended level of security. This is the underlying library intended to make that ultimate goal possible.

This code is not a web browser, so the parts of the spec about "blocking networking requests" aren't relevant. However, calling this out as what a web browser _would do_ can be helpful.

You should consider [web.dev: Content security policy](https://web.dev/articles/csp) **required reading** for understanding CSP.

## Maturity

Implements parsing and evaluation for [CSP2] (2016) and the [CSP3 working draft][CSP3] (April 2024).

* [X] Make it work.
* [ ] Make it right. (In-progress)
* [ ] Make it fast.

> [!CAUTION]
> The core implementation is in-place, and most CSP directives are being parsed correctly. Both the parser (parses the policy into an tree structure) and the evaluator (looks across the tree nodes for issues) will return errors, although the evaluator has not yet been started. Only a single policy at a time is supported. Parsing multiple policies at a time has not yet been started.
>
> **PUBLIC INTERFACES ARE NOT STABLE YET.**

[CSP2]: https://www.w3.org/TR/CSP2/
[CSP3]: https://www.w3.org/TR/2024/WD-CSP3-20240613/
