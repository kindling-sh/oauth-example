package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
	sessionStore *sessions.CookieStore
)

// initAuth sets up the OIDC provider and OAuth2 config.
// Requires AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, PUBLIC_URL.
func initAuth() {
	domain := conf.Auth0Domain
	clientID := conf.Auth0ClientID
	clientSecret := conf.Auth0ClientSecret
	publicURL := conf.PublicURL

	if domain == "" || clientID == "" || clientSecret == "" {
		log.Println("AUTH0 not configured — auth routes disabled")
		return
	}

	issuer := "https://" + domain + "/"
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		log.Printf("WARN: failed to init OIDC provider: %v — auth disabled", err)
		return
	}

	callbackURL := publicURL + "/auth/callback"
	if publicURL == "" {
		callbackURL = "http://localhost:9090/auth/callback"
	}

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	secret := conf.SessionSecret
	if secret == "" {
		secret = "dev-session-secret-change-me"
	}
	sessionStore = sessions.NewCookieStore([]byte(secret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.SameSite = http.SameSiteLaxMode

	log.Printf("Auth0 configured — callback: %s", callbackURL)
}

func authEnabled() bool {
	return oauth2Config != nil
}

// handleLogin redirects the user to Auth0's authorization page.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}

	state, err := randomState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sess, _ := sessionStore.Get(r, "auth")
	sess.Values["state"] = state
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// handleCallback exchanges the auth code for tokens and stores the user in session.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}

	sess, _ := sessionStore.Get(r, "auth")
	expected, ok := sess.Values["state"].(string)
	if !ok || expected == "" || r.URL.Query().Get("state") != expected {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}
	delete(sess.Values, "state")

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}

	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}

	idToken, err := oidcVerifier.Verify(r.Context(), rawID)
	if err != nil {
		log.Printf("id_token verification failed: %v", err)
		http.Error(w, "token verification failed", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Sub   string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	sess.Values["user_email"] = claims.Email
	sess.Values["user_name"] = claims.Name
	sess.Values["user_id"] = claims.Sub
	if err := sess.Save(r, w); err != nil {
		http.Error(w, "session save failed", http.StatusInternalServerError)
		return
	}

	log.Printf("user logged in: %s (%s)", claims.Email, claims.Sub)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the session and redirects to Auth0 logout.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionStore.Get(r, "auth")
	sess.Options.MaxAge = -1
	sess.Save(r, w)

	if authEnabled() {
		logoutURL := "https://" + conf.Auth0Domain + "/v2/logout?client_id=" +
			conf.Auth0ClientID + "&returnTo=" + conf.PublicURL
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleMe returns the current user's info from the session.
func handleMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionStore.Get(r, "auth")
	email, _ := sess.Values["user_email"].(string)
	name, _ := sess.Values["user_name"].(string)
	userID, _ := sess.Values["user_id"].(string)

	if email == "" {
		respond(w, 200, map[string]interface{}{"authenticated": false})
		return
	}
	respond(w, 200, map[string]interface{}{
		"authenticated": true,
		"email":         email,
		"name":          name,
		"id":            userID,
	})
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleAuthStatus returns a JSON summary of the auth config (no secrets).
func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"auth0_configured": authEnabled(),
		"callback_url":     "",
	}
	if authEnabled() {
		status["callback_url"] = oauth2Config.RedirectURL
		status["auth0_domain"] = conf.Auth0Domain
	}
	respond(w, 200, status)
}

// requireAuth is middleware that returns 401 if the user isn't logged in.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled() {
			next(w, r)
			return
		}
		sess, _ := sessionStore.Get(r, "auth")
		if email, _ := sess.Values["user_email"].(string); email == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
			return
		}
		next(w, r)
	}
}
