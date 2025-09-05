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
/* YAML helper types (parsing)   */
/* ----------------------------- */

type DurationYAML struct {
	d time.Duration
}

// Accept either string "1h30m", "3600s", "90m" or number (seconds)
func (dy *DurationYAML) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// try as string first
		var s string
		if err := value.Decode(&s); err == nil {
			s = strings.TrimSpace(s)
			if s == "" {
				dy.d = 0
				return nil
			}
			parsed, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", s, err)
			}
			dy.d = parsed
			return nil
		}
		// try as number (seconds)
		var secs int64
		if err := value.Decode(&secs); err == nil {
			if secs < 0 {
				return fmt.Errorf("duration seconds must be >= 0, got %d", secs)
			}
			dy.d = time.Duration(secs) * time.Second
			return nil
		}
		return fmt.Errorf("duration must be string or number (seconds)")
	default:
		return fmt.Errorf("duration must be a scalar")
	}
}

func (dy DurationYAML) Duration() time.Duration { return dy.d }

type SameSiteYAML struct {
	mode http.SameSite
}

func (ss *SameSiteYAML) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		ss.mode = http.SameSiteStrictMode
	case "none":
		ss.mode = http.SameSiteNoneMode
	case "lax", "":
		ss.mode = http.SameSiteLaxMode
	default:
		return fmt.Errorf("same_site must be one of: Strict, Lax, None (got %q)", s)
	}
	return nil
}
func (ss SameSiteYAML) Mode() http.SameSite { return ss.mode }

/* ----------------------------- */
/* File config (YAML)            */
/* ----------------------------- */

/*
   YAML structure for auth config file
   We define it to keep a layer off the internals of the package in the development phase, as a form of contract
   and to allow for quicker development changes within the internals without breaking clients

*/

type AuthFileConfig struct {
	Manager struct {
		// New/preferred
		AuthPath       string `yaml:"auth_path"`
		AuthLogoutPath string `yaml:"auth_logout_path"`

		JWTSecret          string       `yaml:"jwt_secret"`
		SessionCookieName  string       `yaml:"session_cookie_name"`
		SessionTTL         DurationYAML `yaml:"session_ttl"`
		SameSite           SameSiteYAML `yaml:"same_site"`
		AbsoluteSessionMax DurationYAML `yaml:"absolute_session_max"`

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
/* Construction + validation     */
/* ----------------------------- */

func authConfigFromFileCfg(fc AuthFileConfig) (*AuthConfig, error) {
	ac := &AuthConfig{
		// Session basics — defaults applied below
		SessionCookieName:  fc.Manager.SessionCookieName,
		SessionTTL:         fc.Manager.SessionTTL.Duration(),
		AllowTokenParam:    fc.Manager.AllowTokenParam,
		SameSiteMode:       fc.Manager.SameSite.Mode(),
		JWTSecret:          fc.Manager.JWTSecret,
		AbsoluteSessionMax: fc.Manager.AbsoluteSessionMax.Duration(),
		AuthPath:           strings.TrimRight(fc.Manager.AuthPath, "/"),
		AuthLogoutPath:     strings.TrimRight(fc.Manager.AuthLogoutPath, "/"),
	}

	// Minimal sane defaults
	if ac.SessionCookieName == "" {
		ac.SessionCookieName = defaultSessionCookieName
	}
	if ac.SessionTTL <= 0 {
		ac.SessionTTL = 60 * time.Minute
	}
	if ac.SameSiteMode == 0 { // zero means not set; default to Lax
		ac.SameSiteMode = http.SameSiteLaxMode
	}
	if ac.AbsoluteSessionMax == 0 {
		ac.AbsoluteSessionMax = defaultAbsoluteSessionMax
	}
	// Local
	if fc.Providers.Local.Enabled {
		ac.Local = &LocalConfig{
			Enabled:               true,
			UsersPath:             fc.Providers.Local.UsersPath,
			BootstrapLoginAllowed: fc.Providers.Local.Bootstrap.Allowed,
			BootstrapUser:         fc.Providers.Local.Bootstrap.User,
			BootstrapPasswd:       fc.Providers.Local.Bootstrap.Password,
		}
	}

	// OIDC
	if fc.Providers.OIDC.Enabled {
		if fc.Providers.OIDC.IssuerURL == "" || fc.Providers.OIDC.ClientID == "" ||
			(fc.Providers.OIDC.ClientSecret == "" && fc.Providers.OIDC.Enabled) ||
			fc.Providers.OIDC.RedirectURL == "" {
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

	// LDAP
	if fc.Providers.LDAP.Enabled {
		if fc.Providers.LDAP.URL == "" {
			return nil, fmt.Errorf("ldap.enabled is true but url is empty")
		}
		// Either BindDN+BindPassword (search bind), or direct bind via DN template.
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
