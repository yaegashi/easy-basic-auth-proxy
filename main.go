package main

import (
	"context"
	"embed"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

const (
	EnvListen                       = "EBAP_LISTEN"
	EnvAuthPath                     = "EBAP_AUTH_PATH"
	EnvTargetURL                    = "EBAP_TARGET_URL"
	EnvAccountsDir                  = "EBAP_ACCOUNTS_DIR"
	EnvDevelopment                  = "EBAP_DEVELOPMENT"
	EnvSessionKey                   = "EBAP_SESSION_KEY"
	DefaultListen                   = ":8080"
	DefaultAuthPath                 = "/auth"
	DefaultTargetURL                = "http://127.0.0.1:8081"
	DefaultAccountsDir              = "accounts"
	EasyAuthPrincipalHeaderName     = "X-Ms-Client-Principal"
	EasyAuthPrincipalIdHeaderName   = "X-Ms-Client-Principal-Id"
	EasyAuthPrincipalNameHeaderName = "X-Ms-Client-Principal-Name"
	EasyAuthAccessTokenHeaderName   = "X-Ms-Token-Aad-Access-Token"
	EasyAuthIdTokenHeaderName       = "X-Ms-Token-Aad-Id-Token"
	EasyAuthLoginPath               = "/.auth/login/aad"
	PasswordCharacterSet            = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	SessionAccountValueName         = "SessionAccount"
	SessionCookieName               = "EBAPSession"
)

//go:embed assets templates
var embedFS embed.FS

type SessionAccount struct {
	Username string
}

type Account struct {
	Secrets []Secret `json:"secrets"`
}

type Secret struct {
	Hash        string    `json:"hash"`
	Password    string    `json:"-"`
	Description string    `json:"description"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type App struct {
	Listen       string
	AuthPath     string
	TargetURL    string
	AccountsDir  string
	Development  string
	SessionKey   string
	AccountsMap  *sync.Map
	ProxyHandler *httputil.ReverseProxy
	Template     *template.Template
	SessionStore *sessions.CookieStore
}

func init() {
	gob.Register(&SessionAccount{})
}

func (app *App) Session(r *http.Request) *sessions.Session {
	session, _ := app.SessionStore.Get(r, SessionCookieName)
	session.Options.HttpOnly = true
	session.Options.Secure = true
	session.Options.SameSite = http.SameSiteNoneMode
	return session
}

func (app *App) GeneratePassphrase(n int) string {
	p := make([]byte, n)
	for i := 0; i < n; i++ {
		p[i] = PasswordCharacterSet[rand.Intn(len(PasswordCharacterSet))]
	}
	return string(p)
}

func (app *App) GetUsernameFromCookie(r *http.Request) string {
	if s, ok := app.Session(r).Values[SessionAccountValueName].(*SessionAccount); ok {
		return s.Username
	}
	return ""
}

func (app *App) DebugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	fmt.Fprintf(w, "%s %s\n", r.Method, r.URL)
	for _, key := range keys {
		for _, val := range r.Header[key] {
			fmt.Fprintf(w, "%s: %s\n", key, val)
		}
	}
}

func (app *App) EasyAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != app.AuthPath {
		sub, _ := fs.Sub(embedFS, "assets")
		http.StripPrefix(app.AuthPath, http.FileServer(http.FS(sub))).ServeHTTP(w, r)
		return
	}

	r.ParseForm()
	session := app.Session(r)
	if r.FormValue("logout") != "" {
		session.Values[SessionAccountValueName] = nil
		err := session.Save(r, w)
		if err != nil {
			log.Println(err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	username := app.GetUsernameFromCookie(r)
	if username == "" && app.Development != "" {
		username = r.FormValue("username")
	}
	if username == "" {
		username = r.Header.Get(EasyAuthPrincipalIdHeaderName)
	}
	if username == "" {
		session.Values[SessionAccountValueName] = nil
		nextURL := fmt.Sprintf(EasyAuthLoginPath+"?post_login_redirect_url=%s", url.QueryEscape(app.AuthPath))
		http.Redirect(w, r, nextURL, http.StatusFound)
		return
	}

	account, err := app.LoadAccount(username)
	if err != nil {
		account = &Account{}
	}

	if r.Method == http.MethodPost {
		if r.FormValue("generate") != "" {
			description := r.FormValue("description")
			if description == "" {
				description = fmt.Sprintf("Generated at %s", time.Now().Format(time.RFC3339))
			}
			expiresIn := r.FormValue("expiresIn")
			expiresInTable := map[string]time.Duration{
				"7":   7 * 24 * time.Hour,
				"30":  30 * 24 * time.Hour,
				"365": 365 * 24 * time.Hour,
			}
			expiresInDuration, _ := expiresInTable[expiresIn]
			expiresAt := time.Now().Add(expiresInDuration)
			password := app.GeneratePassphrase(32)
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			secret := Secret{
				Hash:        string(hash),
				Password:    password,
				Description: description,
				ExpiresAt:   expiresAt,
			}
			account.Secrets = append(account.Secrets, secret)
			app.StoreAccount(username, account)
		} else if i, err := strconv.Atoi(r.FormValue("revoke")); err == nil {
			if i >= 0 && i < len(account.Secrets) {
				account.Secrets = append(account.Secrets[:i], account.Secrets[i+1:]...)
				app.StoreAccount(username, account)
			}
		}
	}

	session.Values[SessionAccountValueName] = &SessionAccount{Username: username}
	err = session.Save(r, w)
	if err != nil {
		log.Println(err)
	}

	data := struct {
		AuthPath, Username string
		Secrets            []Secret
	}{
		AuthPath: app.AuthPath,
		Username: username,
		Secrets:  account.Secrets,
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	err = app.Template.ExecuteTemplate(w, "auth.html", data)
	if err != nil {
		log.Println(err)
	}
}

func (app *App) BasicAuth(user, pass string) bool {
	account, err := app.LoadAccount(user)
	if err != nil {
		return false
	}
	for _, secret := range account.Secrets {
		if secret.ExpiresAt.Before(time.Now()) {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(secret.Hash), []byte(pass)) == nil {
			return true
		}
	}
	return false
}

func (app *App) BadRequestHandler(w http.ResponseWriter, r *http.Request) {
	data := struct{ AuthPath, Development string }{
		AuthPath:    app.AuthPath,
		Development: app.Development,
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	err := app.Template.ExecuteTemplate(w, "400.html", data)
	if err != nil {
		log.Println(err)
	}
}

func (app *App) BasicAuthHandler(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok || !app.BasicAuth(username, password) {
		username = ""
	}
	if username == "" {
		username = app.GetUsernameFromCookie(r)
	}
	if username == "" {
		log.Printf("%s Unauthorized %s %s", r.RemoteAddr, r.Method, r.URL)
		r.URL.Scheme = ""
		r.URL.Host = ""
		redirect := r.URL.String()
		if r.Method != http.MethodGet {
			redirect = "/"
		}
		getURL := fmt.Sprintf(EasyAuthLoginPath+"?post_login_redirect_url=%s&redirect=%s", url.QueryEscape(app.AuthPath), url.QueryEscape(redirect))
		data := struct{ AuthPath, GetURL, Message string }{
			AuthPath: app.AuthPath,
			GetURL:   getURL,
			Message:  "Please sign in to open this web site.",
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		err := app.Template.ExecuteTemplate(w, "401.html", data)
		if err != nil {
			log.Println(err)
		}
		return
	}
	log.Printf("%s Proxy %s %s", r.RemoteAddr, r.Method, r.URL)
	app.ProxyHandler.ServeHTTP(w, r)
}

func (app *App) StoreAccount(id string, account *Account) error {
	a := &Account{Secrets: make([]Secret, len(account.Secrets))}
	for i, secret := range account.Secrets {
		a.Secrets[i] = secret
		a.Secrets[i].Password = ""
	}
	app.AccountsMap.Store(id, a)
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	path := filepath.Join(app.AccountsDir, id)
	return os.WriteFile(path, b, 0600)
}

func (app *App) LoadAccount(id string) (*Account, error) {
	aany, ok := app.AccountsMap.Load(id)
	if !ok {
		return nil, fmt.Errorf("account not found")
	}
	account, ok := aany.(*Account)
	if !ok {
		return nil, fmt.Errorf("account not found")
	}
	return account, nil
}

func (app *App) Main(ctx context.Context) error {
	err := os.Mkdir(app.AccountsDir, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	files, err := os.ReadDir(app.AccountsDir)
	if err != nil {
		return err
	}
	app.AccountsMap = &sync.Map{}
	for _, file := range files {
		path := filepath.Join(app.AccountsDir, file.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			log.Println(err)
			continue
		}
		var account *Account
		err = json.Unmarshal(b, &account)
		if err != nil {
			log.Println(err)
			continue
		}
		app.AccountsMap.Store(file.Name(), account)
	}
	u, err := url.Parse(app.TargetURL)
	if err != nil {
		return err
	}
	app.SessionStore = sessions.NewCookieStore([]byte(app.SessionKey))
	app.ProxyHandler = httputil.NewSingleHostReverseProxy(u)
	app.Template, _ = template.ParseFS(embedFS, "templates/*")
	mux := http.NewServeMux()
	mux.Handle(filepath.Join(app.AuthPath, "assets")+"/", http.StripPrefix(app.AuthPath, http.FileServer(http.FS(embedFS))))
	mux.HandleFunc(filepath.Join(app.AuthPath, "debug")+"/", app.DebugHandler)
	mux.HandleFunc(app.AuthPath, app.EasyAuthHandler)
	mux.HandleFunc("/.auth/login/", app.BadRequestHandler)
	mux.HandleFunc("/.auth/logout", app.BadRequestHandler)
	mux.HandleFunc("/", app.BasicAuthHandler)
	log.Println("Listening on ", app.Listen)
	return http.ListenAndServe(app.Listen, mux)
}

func main() {
	app := App{
		Listen:      os.Getenv(EnvListen),
		AuthPath:    os.Getenv(EnvAuthPath),
		TargetURL:   os.Getenv(EnvTargetURL),
		AccountsDir: os.Getenv(EnvAccountsDir),
		Development: os.Getenv(EnvDevelopment),
		SessionKey:  os.Getenv(EnvSessionKey),
	}
	if app.Listen == "" {
		app.Listen = DefaultListen
	}
	if app.AuthPath == "" {
		app.AuthPath = DefaultAuthPath
	}
	if app.TargetURL == "" {
		app.TargetURL = DefaultTargetURL
	}
	if app.AccountsDir == "" {
		app.AccountsDir = DefaultAccountsDir
	}
	err := app.Main(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
