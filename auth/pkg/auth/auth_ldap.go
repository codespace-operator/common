package auth

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const LDAP_PROVIDER = "ldap"

// LDAPAuthProvider adds username/password auth like Local
type LDAPAuthProvider interface {
	Provider
	Authenticate(username, password string) (*TokenClaims, error)
}

// LDAPConfig controls how we find and bind users and map groups->roles
type LDAPConfig struct {
	Enabled bool

	// Connection
	URL                string // e.g. ldaps://ldap.example.com:636 or ldap://host:389
	StartTLS           bool   // if true and URL is ldap://, do StartTLS
	InsecureSkipVerify bool   // only for testing; do not use in prod

	// Service bind for search (optional). If empty, you can bind as the user directly (via UserDNTemplate).
	BindDN       string
	BindPassword string

	// How to locate the user
	UserBaseDN      string // e.g. "ou=People,dc=example,dc=com"
	UserFilter      string // e.g. "(uid={username})" or "(sAMAccountName={username})"
	UserDNTemplate  string // e.g. "uid={username},ou=People,dc=example,dc=com" (skip search if set)
	UsernameAttr    string // default: "uid" (or "sAMAccountName" for AD)
	EmailAttr       string // default: "mail"
	DisplayNameAttr string // optional: "cn"

	// How to resolve groups/roles
	GroupBaseDN  string              // e.g. "ou=Groups,dc=example,dc=com"
	GroupFilter  string              // e.g. "(member={userDN})" or "(memberUid={username})"
	GroupAttr    string              // attribute to read as group “name”, default: "cn"
	RoleMapping  map[string][]string // groupValue (name or DN) -> roles
	DefaultRoles []string            // fallback when no mapping matches; default ["viewer"]

	// Optional username canonicalization (trim spaces, lower-case, etc.)
	ToLowerUsername bool
}

// internal iface to allow tests/mocks if you want to add them later
type ldapConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close()
}

type realConn struct{ *ldap.Conn }

func (c *realConn) Bind(u, p string) error { return c.Conn.Bind(u, p) }
func (c *realConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.Conn.Search(r)
}
func (c *realConn) Close() {
	if err := c.Conn.Close(); err != nil {
		c.Debug.Printf("LDAP connection close error: %v", err)
	}
}

type LDAPProvider struct {
	ProviderBase
	cfg  *LDAPConfig
	dial func(url string, startTLS bool, insecure bool) (ldapConn, error)
}

func NewLDAPProvider(cfg *LDAPConfig, tm TokenManager, logger *slog.Logger) (*LDAPProvider, error) {
	if cfg == nil {
		return nil, errors.New("nil LDAP config")
	}
	if !cfg.Enabled {
		return nil, errors.New("ldap disabled")
	}
	if cfg.URL == "" {
		return nil, errors.New("ldap url required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "ldap-auth")

	lp := &LDAPProvider{
		ProviderBase: NewProviderBase(tm, logger),
		cfg:          fillLDAPDefaults(cfg),
		dial: func(u string, startTLS, insecure bool) (ldapConn, error) {
			conn, err := ldap.DialURL(u)
			if err != nil {
				return nil, err
			}
			if startTLS {
				tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
				if err := conn.StartTLS(tlsCfg); err != nil {
					if cerr := conn.Close(); cerr != nil {
						logger.Debug("LDAP connection close error", "error", cerr)
					}
					return nil, err
				}
			}
			return &realConn{conn}, nil
		},
	}
	return lp, nil
}

func fillLDAPDefaults(c *LDAPConfig) *LDAPConfig {
	out := *c
	if out.UsernameAttr == "" {
		out.UsernameAttr = "uid"
	}
	if out.EmailAttr == "" {
		out.EmailAttr = "mail"
	}
	if out.GroupAttr == "" {
		out.GroupAttr = "cn"
	}
	if len(out.DefaultRoles) == 0 {
		out.DefaultRoles = []string{"viewer"}
	}
	return &out
}

func (lp *LDAPProvider) Name() string { return LDAP_PROVIDER }

// Redirect-style flow is not supported for LDAP (same as Local)
func (lp *LDAPProvider) StartAuth(w http.ResponseWriter, r *http.Request, redirectAfter string) error {
	return errors.New("ldap authentication does not support redirect flow")
}

func (lp *LDAPProvider) HandleCallback(w http.ResponseWriter, r *http.Request) (*TokenClaims, error) {
	return nil, errors.New("ldap authentication does not support callback flow")
}

func (lp *LDAPProvider) Logout(w http.ResponseWriter, r *http.Request) error {
	lp.logger.Debug("LDAP logout completed (local only)")
	return nil
}

func (lp *LDAPProvider) ValidateToken(token string) (*TokenClaims, error) {
	return lp.tokenManager.ValidateToken(token)
}

// Authenticate binds against LDAP, resolves groups, maps to roles, and returns claims.
func (lp *LDAPProvider) Authenticate(username, password string) (*TokenClaims, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, errors.New("invalid credentials")
	}
	user := username
	if lp.cfg.ToLowerUsername {
		user = strings.ToLower(strings.TrimSpace(user))
	}

	conn, err := lp.dial(lp.cfg.URL, lp.cfg.StartTLS, lp.cfg.InsecureSkipVerify)
	if err != nil {
		lp.logger.Debug("LDAP dial failed", "error", err)
		return nil, errors.New("authentication failed")
	}
	defer conn.Close()

	// Resolve user DN
	userDN := ""
	userAttrs := map[string]string{}

	// Strategy A: search with service bind (if configured)
	if lp.cfg.BindDN != "" && lp.cfg.BindPassword != "" {
		if err := conn.Bind(lp.cfg.BindDN, lp.cfg.BindPassword); err != nil {
			lp.logger.Debug("LDAP service bind failed", "error", err)
			return nil, errors.New("authentication failed")
		}
		if lp.cfg.UserDNTemplate != "" {
			userDN = strings.ReplaceAll(lp.cfg.UserDNTemplate, "{username}", ldap.EscapeFilter(user))
		} else {
			if lp.cfg.UserBaseDN == "" || lp.cfg.UserFilter == "" {
				return nil, errors.New("ldap user search not configured (UserBaseDN/UserFilter)")
			}
			filter := strings.ReplaceAll(lp.cfg.UserFilter, "{username}", ldap.EscapeFilter(user))
			req := ldap.NewSearchRequest(
				lp.cfg.UserBaseDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
				filter,
				[]string{lp.cfg.UsernameAttr, lp.cfg.EmailAttr, lp.cfg.DisplayNameAttr},
				nil,
			)
			res, err := conn.Search(req)
			if err != nil || len(res.Entries) != 1 {
				lp.logger.Debug("LDAP user search failed", "err", err, "count", len(res.Entries))
				return nil, errors.New("invalid credentials")
			}
			entry := res.Entries[0]
			userDN = entry.DN
			// cache known attrs from the search
			if v := entry.GetAttributeValue(lp.cfg.UsernameAttr); v != "" {
				userAttrs["username"] = v
			}
			if v := entry.GetAttributeValue(lp.cfg.EmailAttr); v != "" {
				userAttrs["email"] = v
			}
			if v := entry.GetAttributeValue(lp.cfg.DisplayNameAttr); v != "" {
				userAttrs["name"] = v
			}
		}
	} else {
		// Strategy B: direct user DN template (no service bind)
		if lp.cfg.UserDNTemplate == "" {
			return nil, errors.New("either BindDN+BindPassword+search or UserDNTemplate is required")
		}
		userDN = strings.ReplaceAll(lp.cfg.UserDNTemplate, "{username}", ldap.EscapeFilter(user))
	}

	// Bind as the user (this verifies the password)
	if err := conn.Bind(userDN, password); err != nil {
		lp.logger.Debug("LDAP user bind failed", "error", err)
		return nil, errors.New("invalid credentials")
	}

	// Ensure we have email/username after user bind (if not filled already)
	if userAttrs["email"] == "" || userAttrs["username"] == "" {
		if lp.cfg.UserBaseDN != "" && lp.cfg.UserFilter != "" {
			filter := strings.ReplaceAll(lp.cfg.UserFilter, "{username}", ldap.EscapeFilter(user))
			req := ldap.NewSearchRequest(
				lp.cfg.UserBaseDN,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false,
				filter,
				[]string{lp.cfg.UsernameAttr, lp.cfg.EmailAttr, lp.cfg.DisplayNameAttr},
				nil,
			)
			if res, err := conn.Search(req); err == nil && len(res.Entries) >= 1 {
				entry := res.Entries[0]
				if userAttrs["username"] == "" {
					if v := entry.GetAttributeValue(lp.cfg.UsernameAttr); v != "" {
						userAttrs["username"] = v
					}
				}
				if userAttrs["email"] == "" {
					if v := entry.GetAttributeValue(lp.cfg.EmailAttr); v != "" {
						userAttrs["email"] = v
					}
				}
				if userAttrs["name"] == "" {
					if v := entry.GetAttributeValue(lp.cfg.DisplayNameAttr); v != "" {
						userAttrs["name"] = v
					}
				}
			}
		}
	}
	if userAttrs["username"] == "" {
		userAttrs["username"] = user // fallback
	}

	// Resolve groups -> roles
	roles := lp.cfg.DefaultRoles
	groups := []string{}
	if lp.cfg.GroupBaseDN != "" && lp.cfg.GroupFilter != "" {
		filter := lp.cfg.GroupFilter
		filter = strings.ReplaceAll(filter, "{username}", ldap.EscapeFilter(user))
		filter = strings.ReplaceAll(filter, "{userDN}", ldap.EscapeFilter(userDN))

		req := ldap.NewSearchRequest(
			lp.cfg.GroupBaseDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false,
			filter,
			[]string{lp.cfg.GroupAttr, "dn"},
			nil,
		)
		if res, err := conn.Search(req); err == nil {
			for _, e := range res.Entries {
				if name := e.GetAttributeValue(lp.cfg.GroupAttr); name != "" {
					groups = append(groups, name)
				} else {
					groups = append(groups, e.DN)
				}
			}
		}
		// Map to roles (dedupe)
		mapped := make(map[string]struct{})
		for _, g := range groups {
			// check name and DN keys
			if rs, ok := lp.cfg.RoleMapping[g]; ok {
				for _, r := range rs {
					if r = strings.TrimSpace(r); r != "" {
						mapped[r] = struct{}{}
					}
				}
			}
		}
		if len(mapped) > 0 {
			roles = roles[:0]
			for r := range mapped {
				roles = append(roles, r)
			}
		}
	}

	claims := &TokenClaims{
		Sub:       LDAP_PROVIDER + ":" + userAttrs["username"], // stable subject
		Username:  userAttrs["username"],
		Email:     userAttrs["email"],
		Roles:     roles,
		Provider:  lp.Name(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(), // will be set by token manager
	}

	lp.logger.Info("LDAP authentication successful",
		"user", userAttrs["username"],
		"email", userAttrs["email"],
		"roles", roles,
	)

	return claims, nil
}
