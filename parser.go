package csp

import "regexp"

type Policy struct{}

func Parse(policy string) {
}

// isBase64 doesn't try to decode anything. Rather, it just checks if the string
// matches the allowed list of characters. A value of `true` means that he
// string is _probably_ base64-encoded. A value if `false` means that the string
// is definitely not base64-encoded.
func isBase64(s string) bool {
	reBase64 := regexp.MustCompile(`^[a-zA-Z0-9+/]*={0,2}$`)

	return reBase64.MatchString(s)
}

// isASCII checks if the string is entirely ASCII, excluding non-printable
// characters (e.g., NUL, DEL). A value of `true` means that the string is
// comprised entirely of printable ASCII characters. A value of `false` means
// that the string contains non-printable characters.
func isASCII(s string) bool {
	reASCII := regexp.MustCompile(`^[\x20-\x7E]*$`)

	return reASCII.MatchString(s)
}
