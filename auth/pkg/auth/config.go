package auth

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

/* ----------------------------- */
/* Simplified config (standard types) */
/* ----------------------------- */

type AuthFileConfig struct {
	Manager struct {
		AuthPath       string `yaml:"auth_path"`
		AuthLogoutPath string `yaml:"auth_logout_path"`

		JWTSecret         string `yaml:"jwt_secret"`
		SessionCookieName string `yaml:"session_cookie_name"`

		SessionTTL         string `yaml:"session_ttl"`
		AbsoluteSessionMax string `yaml:"absolute_session_max"`

		SameSite string `yaml:"same_site"`

		AllowTokenParam bool `yaml:"allow_token_param"`
	} `yaml:"manager"`

	Providers struct {
		Local struct {
			Enabled   bool   `yaml:"enabled"`
			UsersPath string `yaml:"users_path"`
			Bootstrap struct {
				Allowed  bool   `yaml:"allowed"`
				User     string `yaml:"user"`
				Password string `yaml:"password"`
			} `yaml:"bootstrap"`
		} `yaml:"local"`

		OIDC struct {
			Enabled            bool     `yaml:"enabled"`
			IssuerURL          string   `yaml:"issuer_url"`
			ClientID           string   `yaml:"client_id"`
			ClientSecret       string   `yaml:"client_secret"`
			RedirectURL        string   `yaml:"redirect_url"`
			Scopes             []string `yaml:"scopes"`
			InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
		} `yaml:"oidc"`

		LDAP struct {
			Enabled            bool   `yaml:"enabled"`
			URL                string `yaml:"url"`
			StartTLS           bool   `yaml:"start_tls"`
			InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
			BindDN             string `yaml:"bind_dn"`
			BindPassword       string `yaml:"bind_password"`

			User struct {
				DNTemplate string `yaml:"dn_template"`
				BaseDN     string `yaml:"base_dn"`
				Filter     string `yaml:"filter"`
				Attrs      struct {
					Username    string `yaml:"username"`
					Email       string `yaml:"email"`
					DisplayName string `yaml:"display_name"`
				} `yaml:"attrs"`
				ToLowerUsername bool `yaml:"to_lower_username"`
			} `yaml:"user"`

			Group struct {
				BaseDN string `yaml:"base_dn"`
				Filter string `yaml:"filter"`
				Attr   string `yaml:"attr"`
			} `yaml:"group"`

			Roles struct {
				Mapping map[string][]string `yaml:"mapping"`
				Default []string            `yaml:"default"`
			} `yaml:"roles"`
		} `yaml:"ldap"`
	} `yaml:"providers"`
}

/* ----------------------------- */
/* Helper functions for parsing   */
/* ----------------------------- */

// parseDuration accepts either a duration string like "1h30m" or number of seconds
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// Try parsing as duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Try parsing as seconds (for backwards compatibility)
	if secs, err := parseAsSeconds(s); err == nil {
		return time.Duration(secs) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration %q: expected format like '1h30m' or number of seconds", s)
}

func parseAsSeconds(s string) (int64, error) {
	// You can implement parsing as seconds if needed
	// For now, just return an error to force duration format
	return 0, fmt.Errorf("not a number")
}

// parseSameSite converts string to http.SameSite
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax", "":
		return http.SameSiteLaxMode
	default:
		// Default to Lax for invalid values
		return http.SameSiteLaxMode
	}
}

/* ----------------------------- */
/* Construction + validation     */
/* ----------------------------- */

func authConfigFromFileCfg(fc AuthFileConfig) (*AuthConfig, error) {
	// Parse duration fields
	sessionTTL, err := parseDuration(fc.Manager.SessionTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid session_ttl: %w", err)
	}

	absoluteSessionMax, err := parseDuration(fc.Manager.AbsoluteSessionMax)
	if err != nil {
		return nil, fmt.Errorf("invalid absolute_session_max: %w", err)
	}

	ac := &AuthConfig{
		SessionCookieName:  fc.Manager.SessionCookieName,
		SessionTTL:         sessionTTL,
		AllowTokenParam:    fc.Manager.AllowTokenParam,
		SameSiteMode:       parseSameSite(fc.Manager.SameSite),
		JWTSecret:          fc.Manager.JWTSecret,
		AbsoluteSessionMax: absoluteSessionMax,
		AuthPath:           strings.TrimRight(fc.Manager.AuthPath, "/"),
		AuthLogoutPath:     strings.TrimRight(fc.Manager.AuthLogoutPath, "/"),
	}

	// Apply defaults
	if ac.SessionCookieName == "" {
		ac.SessionCookieName = defaultSessionCookieName
	}
	if ac.SessionTTL <= 0 {
		ac.SessionTTL = 60 * time.Minute
	}
	if ac.SameSiteMode == 0 { // shouldn't happen with parseSameSite, but just in case
		ac.SameSiteMode = http.SameSiteLaxMode
	}
	if ac.AbsoluteSessionMax == 0 {
		ac.AbsoluteSessionMax = defaultAbsoluteSessionMax
	}

	// Local provider
	if fc.Providers.Local.Enabled {
		ac.Local = &LocalConfig{
			Enabled:               true,
			UsersPath:             fc.Providers.Local.UsersPath,
			BootstrapLoginAllowed: fc.Providers.Local.Bootstrap.Allowed,
			BootstrapUser:         fc.Providers.Local.Bootstrap.User,
			BootstrapPasswd:       fc.Providers.Local.Bootstrap.Password,
		}
	}

	// OIDC provider
	if fc.Providers.OIDC.Enabled {
		if fc.Providers.OIDC.IssuerURL == "" || fc.Providers.OIDC.ClientID == "" ||
			fc.Providers.OIDC.ClientSecret == "" || fc.Providers.OIDC.RedirectURL == "" {
			return nil, fmt.Errorf("oidc.enabled is true but required fields are missing (issuer_url, client_id, client_secret, redirect_url)")
		}
		ac.OIDC = &OIDCConfig{
			Enabled:            true,
			IssuerURL:          fc.Providers.OIDC.IssuerURL,
			ClientID:           fc.Providers.OIDC.ClientID,
			ClientSecret:       fc.Providers.OIDC.ClientSecret,
			RedirectURL:        fc.Providers.OIDC.RedirectURL,
			Scopes:             fc.Providers.OIDC.Scopes,
			InsecureSkipVerify: fc.Providers.OIDC.InsecureSkipVerify,
		}
	}

	// LDAP provider
	if fc.Providers.LDAP.Enabled {
		if fc.Providers.LDAP.URL == "" {
			return nil, fmt.Errorf("ldap.enabled is true but url is empty")
		}
		if fc.Providers.LDAP.BindDN == "" && fc.Providers.LDAP.User.DNTemplate == "" {
			return nil, fmt.Errorf("ldap: either bind_dn (+ bind_password) or user.dn_template must be provided")
		}
		if fc.Providers.LDAP.BindDN != "" && fc.Providers.LDAP.BindPassword == "" {
			return nil, fmt.Errorf("ldap: bind_dn provided but bind_password is empty")
		}

		ac.LDAP = &LDAPConfig{
			Enabled:            true,
			URL:                fc.Providers.LDAP.URL,
			StartTLS:           fc.Providers.LDAP.StartTLS,
			InsecureSkipVerify: fc.Providers.LDAP.InsecureSkipVerify,

			BindDN:       fc.Providers.LDAP.BindDN,
			BindPassword: fc.Providers.LDAP.BindPassword,

			UserDNTemplate:  fc.Providers.LDAP.User.DNTemplate,
			UserBaseDN:      fc.Providers.LDAP.User.BaseDN,
			UserFilter:      strings.TrimSpace(fc.Providers.LDAP.User.Filter),
			UsernameAttr:    fc.Providers.LDAP.User.Attrs.Username,
			EmailAttr:       fc.Providers.LDAP.User.Attrs.Email,
			DisplayNameAttr: fc.Providers.LDAP.User.Attrs.DisplayName,
			ToLowerUsername: fc.Providers.LDAP.User.ToLowerUsername,

			GroupBaseDN: fc.Providers.LDAP.Group.BaseDN,
			GroupFilter: strings.TrimSpace(fc.Providers.LDAP.Group.Filter),
			GroupAttr:   fc.Providers.LDAP.Group.Attr,

			RoleMapping:  fc.Providers.LDAP.Roles.Mapping,
			DefaultRoles: fc.Providers.LDAP.Roles.Default,
		}
	}

	return ac, nil
}

/* ----------------------------- */
/* Public helpers                */
/* ----------------------------- */

func LoadAuthConfigFromFile(path string) (*AuthConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	return LoadAuthConfigFromYAML(b)
}

func LoadAuthConfigFromYAML(b []byte) (*AuthConfig, error) {
	var fc AuthFileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return nil, fmt.Errorf("parse auth yaml: %w", err)
	}
	return authConfigFromFileCfg(fc)
}

// FromFileConfig converts an AuthFileConfig (YAML shape) into a runtime AuthConfig.
func FromFileConfig(fc AuthFileConfig) (*AuthConfig, error) {
	return authConfigFromFileCfg(fc)
}

func ParseFileConfigYAML(b []byte) (AuthFileConfig, error) {
	var fc AuthFileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return AuthFileConfig{}, err
	}
	return fc, nil
}
