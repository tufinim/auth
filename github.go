package identity

import (
	"github.com/google/go-github/github"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"github.com/tufin/orca/ceribro/config"
	"github.com/tufin/orca/go-common"
	"golang.org/x/oauth2"
	ghoauth "golang.org/x/oauth2/github"

	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
)

var (
	oauthConf = &oauth2.Config{
		ClientID:     getEnvVar("GITHUB_CLIENT_ID"),
		ClientSecret: getEnvVar("GITHUB_CLIENT_SECRET"),
		Endpoint:     ghoauth.Endpoint,
		Scopes:       []string{"user", "repo"},
	}
	store = sessions.NewCookieStore([]byte("something-very-secret"))
	users = initUsers()
)

const (
	// session
	sessionName       = "tufin"
	sessionUser       = "user"
	sessionOauthState = "oauthState"
)

func HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Errorf("Failed to get session '%s' with %v", sessionName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// state should be a random generated string
	// (CSRF see: RFC: http://tools.ietf.org/html/rfc6749#section-10.12)
	oauthState := randToken()
	session.Values[sessionOauthState] = oauthState
	session.Save(r, w)
	url := oauthConf.AuthCodeURL(oauthState, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, sessionName)
	if err != nil {
		log.Errorf("Failed to get session '%s' with %v", sessionName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ctx := context.Background()

	oauthState := session.Values[sessionOauthState].(string)
	state := r.FormValue("state")
	if state != oauthState {
		Unauthorized(w, r)
		return
	}

	code := r.FormValue("code")
	token, err := oauthConf.Exchange(ctx, code)
	if err != nil {
		log.Errorf("oauth exchange failed with '%s'", err)
		Unauthorized(w, r)
		return
	}

	oauthClient := oauthConf.Client(ctx, token)
	client := github.NewClient(oauthClient)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		log.Errorf("Failed to get GitHub user with '%s'", err)
		Unauthorized(w, r)
		return
	}
	log.Infof("Login as GitHub user %s (%s)", user.GetName(), user.GetLogin())

	session.Values[sessionUser] = user.GetLogin()
	session.Save(r, w)

	http.Redirect(w, r, "/ui", http.StatusTemporaryRedirect)
}

func IsValid(r *http.Request) bool {

	ret := false
	if !isAuthRequired() {
		ret = true
	} else {
		session, err := store.Get(r, sessionName)
		if err != nil {
			log.Error("Failed to get session from request. ", err)
		} else {
			user := session.Values[sessionUser]
			if user != nil && users.Contains(user.(string)) {
				ret = true
			}
		}
	}

	return ret
}

func Unauthorized(w http.ResponseWriter, r *http.Request) {

	http.Redirect(w, r, "/welcome/index.html", http.StatusTemporaryRedirect)
}

func randToken() string {

	b := make([]byte, 32)
	rand.Read(b)

	return base64.StdEncoding.EncodeToString(b)
}

func initUsers() common.List {

	ret := common.NewList()
	admins := os.Getenv(config.AdminUsers)
	if admins == "" {
		log.Infof("Empty %s environment variable, using default", config.AdminUsers)
		admins = "reuvenharrison,tsafya,effoeffi,zvikaga"
	}
	ret.AddItems(strings.Split(admins, ","))
	log.Infof("Admin users: %s", admins)

	return ret
}
