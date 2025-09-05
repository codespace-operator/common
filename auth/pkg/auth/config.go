package auth

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type authFileConfig struct {
	Session struct {
		CookieName      string `yaml:"cookie_name"`
		TTLMinutes      int    `yaml:"ttl_minutes"`
		AllowTokenParam bool   `yaml:"allow_token_param"`
		SameSite        string `yaml:"same_site"` // Strict|Lax|None
	} `yaml:"session"`

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
			User               struct {
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

func sameSiteFromString(s string) (mode http.SameSite) {
	switch s {
	case "Strict", "strict":
		return http.SameSiteStrictMode
	case "None", "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// LoadAuthConfigFromFile reads YAML and converts to AuthConfig
func LoadAuthConfigFromFile(path string) (*AuthConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth config: %w", err)
	}
	var fc authFileConfig
	if err := yaml.Unmarshal(raw, &fc); err != nil {
		return nil, fmt.Errorf("parse auth config: %w", err)
	}

	ac := &AuthConfig{
		SessionCookieName: fc.Session.CookieName,
		SessionTTL:        time.Duration(fc.Session.TTLMinutes) * time.Minute,
		AllowTokenParam:   fc.Session.AllowTokenParam,
		SameSiteMode:      sameSiteFromString(fc.Session.SameSite),

		// providers filled below
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
		ac.LDAP = &LDAPConfig{
			Enabled:            true,
			URL:                fc.Providers.LDAP.URL,
			StartTLS:           fc.Providers.LDAP.StartTLS,
			InsecureSkipVerify: fc.Providers.LDAP.InsecureSkipVerify,

			BindDN:       fc.Providers.LDAP.BindDN,
			BindPassword: fc.Providers.LDAP.BindPassword,

			UserBaseDN:      fc.Providers.LDAP.User.BaseDN,
			UserFilter:      fc.Providers.LDAP.User.Filter,
			UserDNTemplate:  fc.Providers.LDAP.User.DNTemplate,
			UsernameAttr:    fc.Providers.LDAP.User.Attrs.Username,
			EmailAttr:       fc.Providers.LDAP.User.Attrs.Email,
			DisplayNameAttr: fc.Providers.LDAP.User.Attrs.DisplayName,

			GroupBaseDN:  fc.Providers.LDAP.Group.BaseDN,
			GroupFilter:  fc.Providers.LDAP.Group.Filter,
			GroupAttr:    fc.Providers.LDAP.Group.Attr,
			RoleMapping:  fc.Providers.LDAP.Roles.Mapping,
			DefaultRoles: fc.Providers.LDAP.Roles.Default,

			ToLowerUsername: fc.Providers.LDAP.User.ToLowerUsername,
		}
	}

	return ac, nil
}
