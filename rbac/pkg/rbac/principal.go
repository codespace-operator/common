package rbac

import "net/http"

// Principal is the minimal identity RBAC needs.
type Principal struct {
	Subject string
	Roles   []string
}

// PrincipalExtractor pulls a Principal from an HTTP request (e.g., from context).
type PrincipalExtractor func(*http.Request) (*Principal, error)
