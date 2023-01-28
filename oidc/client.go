package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/exp/slices"
)

type Client struct {
	providerURL string
	config      ClientConfig
	oidConfig   oidConfig

	pendingStates map[string]struct{}
	pendingNonces map[string]struct{}

	jwkCache *jwk.Cache
	jwkSet   jwk.Set
}

type ClientConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

type oidConfig struct {
	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	JWKsURI               string `json:"jwks_uri"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`

	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	ServiceDocumentation string `json:"service_documentation"`
}

func NewClient(providerURL string, config ClientConfig) (*Client, error) {
	client := &Client{
		providerURL:   strings.TrimSuffix(providerURL, "/"),
		config:        config,
		pendingStates: make(map[string]struct{}),
		pendingNonces: make(map[string]struct{}),
	}

	if err := client.fetchOpenIDConfig(); err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}

	if err := client.verifyOpenIDConfig(); err != nil {
		return nil, fmt.Errorf("verify OpenID configuration: %w", err)
	}

	client.jwkCache = jwk.NewCache(context.Background(), jwk.WithRefreshWindow(1*time.Hour))
	client.jwkCache.Register(client.oidConfig.JWKsURI, jwk.WithMinRefreshInterval(1*time.Hour))
	_, err := client.jwkCache.Refresh(context.Background(), client.oidConfig.JWKsURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWK set: %w", err)
	}
	client.jwkSet = jwk.NewCachedSet(client.jwkCache, client.oidConfig.JWKsURI)

	return client, nil
}

func (c *Client) InitiateAuthFlow(w http.ResponseWriter, r *http.Request, scopes []string) {
	state := generateToken(10)
	nonce := generateToken(10)
	c.pendingStates[state] = struct{}{}
	c.pendingNonces[nonce] = struct{}{}
	go func() {
		time.Sleep(10 * time.Minute)
		delete(c.pendingStates, state)
		delete(c.pendingNonces, nonce)
	}()

	params := url.Values{}
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", c.config.RedirectURI)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("response_type", "code")
	params.Set("response_mode", "query")
	params.Set("state", state)
	params.Set("nonce", nonce)

	http.Redirect(w, r, c.oidConfig.AuthorizationEndpoint+"?"+params.Encode(), http.StatusSeeOther)
}

func (c *Client) FinishAuthFlow(w http.ResponseWriter, r *http.Request) (access string, refresh string, id string, err error) {
	query := r.URL.Query()

	state := query.Get("state")
	if _, ok := c.pendingStates[state]; !ok {
		return "", "", "", fmt.Errorf("auth flow failed: %w", ErrInvalidState)
	}
	delete(c.pendingStates, state)

	error := query.Get("error")
	if error != "" {
		return "", "", "", fmt.Errorf("auth flow failed: %w", errors.New(error))
	}

	code := query.Get("code")
	if code == "" {
		return "", "", "", fmt.Errorf("auth flow failed: missing code query parameter")
	}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", c.config.RedirectURI)
	req, err := http.NewRequest(http.MethodPost, c.oidConfig.TokenEndpoint, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return "", "", "", fmt.Errorf("token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.config.ClientID), url.QueryEscape(c.config.ClientSecret))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("token request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		type response struct {
			Error string `json:"error"`
		}
		var data response
		json.NewDecoder(res.Body).Decode(&data)
		if data.Error == "" {
			return "", "", "", fmt.Errorf("token request failed with status code %d", res.StatusCode)
		}
		return "", "", "", fmt.Errorf("token request: %w", errors.New(data.Error))
	}
	type response struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token,omitempty"`
	}
	var data response
	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return "", "", "", fmt.Errorf("decode token request response: %w", err)
	}
	if strings.ToLower(data.TokenType) != "bearer" {
		return "", "", "", fmt.Errorf("token request: unsupported token type")
	}

	if err = c.VerifyIDToken(data.IDToken); err != nil {
		return "", "", "", fmt.Errorf("token request: %w", err)
	}

	return data.AccessToken, data.RefreshToken, data.IDToken, nil
}

func (c *Client) VerifyIDToken(idToken string) error {
	refreshed := false
	for {
		_, err := jwt.ParseString(idToken, jwt.WithKeySet(c.jwkSet, jws.WithRequireKid(false)), jwt.WithValidate(true), jwt.WithAcceptableSkew(1*time.Minute), jwt.WithIssuer(c.providerURL), jwt.WithAudience(c.config.ClientID))
		if err == nil {
			return nil
		}
		if errors.Is(err, jwt.ErrTokenExpired()) {
			return ErrExpiredToken
		}
		if jwt.IsValidationError(err) || refreshed {
			break
		}
		c.jwkCache.Refresh(context.Background(), c.oidConfig.JWKsURI)
		refreshed = true
	}
	return ErrInvalidToken
}

type UserInfo struct {
	Subject       string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (c *Client) FetchUserInfo(userID, accessToken string) (UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.oidConfig.UserInfoEndpoint, nil)
	if err != nil {
		return UserInfo{}, fmt.Errorf("fetch user info: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("fetch user info: %w", err)
	}
	defer resp.Body.Close()
	var info UserInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return UserInfo{}, fmt.Errorf("decode user info: %w", err)
	}
	if info.Subject != userID {
		return UserInfo{}, errors.New("fetch user info: user ID does not match requested user ID")
	}
	return info, nil
}

func ParseJWT(token string) (jwt.Token, error) {
	t, err := jwt.ParseString(token, jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, ErrInvalidToken
	}
	return t, nil
}

func (c *Client) fetchOpenIDConfig() error {
	res, err := http.Get(c.providerURL + "/.well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("fetch OpenID configuration: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch OpenID configuration failed with status code %d", res.StatusCode)
	}

	var config oidConfig
	err = json.NewDecoder(res.Body).Decode(&config)
	if err != nil {
		return fmt.Errorf("decode OpenID configuration: %w", err)
	}

	if config.Issuer != c.providerURL {
		return fmt.Errorf("issuer in OpenID configuration does not match provider URL")
	}

	c.oidConfig = config
	return nil
}

func (c *Client) verifyOpenIDConfig() error {
	if c.oidConfig.Issuer != c.providerURL {
		return errors.New("issuer does not match providerURL")
	}
	if c.oidConfig.AuthorizationEndpoint == "" {
		return errors.New("empty authorization endpoint")
	}
	if c.oidConfig.JWKsURI == "" {
		return errors.New("empty JWKs URI")
	}
	if c.oidConfig.TokenEndpoint == "" {
		return errors.New("empty token endpoint")
	}
	if c.oidConfig.UserInfoEndpoint == "" {
		return errors.New("empty user info endpoint")
	}
	if !slices.Contains(c.oidConfig.GrantTypesSupported, "authorization_code") {
		return errors.New("provider does not support authorization_code grant type")
	}
	if !slices.Contains(c.oidConfig.ResponseTypesSupported, "code") {
		return errors.New("provider does not support code response type")
	}
	if !slices.Contains(c.oidConfig.ScopesSupported, "openid") || !slices.Contains(c.oidConfig.ScopesSupported, "profile") || !slices.Contains(c.oidConfig.ScopesSupported, "email") {
		return errors.New("provider does not support all necessary scopes (openid, profile, email)")
	}
	if !slices.Contains(c.oidConfig.TokenEndpointAuthMethodsSupported, "client_secret_basic") {
		return errors.New("provider does not support client_secret_basic token endpoint auth method")
	}
	return nil
}

func generateToken(length int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}
