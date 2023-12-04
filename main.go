package main

import (
	"context"
	"embed"
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
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	EnvListen                       = "EBAP_LISTEN"
	EnvAuthURI                      = "EBAP_AUTH_URI"
	EnvUpstreamURI                  = "EBAP_UPSTREAM_URI"
	EnvAccountDir                   = "EBAP_ACCOUNT_DIR"
	DefaultListen                   = ":8080"
	DefaultUpstreamURI              = "http://127.0.0.1:8081"
	DefaultAccountDir               = "accounts"
	DefaultAuthURI                  = "/auth"
	EasyAuthPrincipalHeaderName     = "X-Ms-Client-Principal"
	EasyAuthPrincipalIdHeaderName   = "X-Ms-Client-Principal-Id"
	EasyAuthPrincipalNameHeaderName = "X-Ms-Client-Principal-Name"
	EasyAuthAccessTokenHeaderName   = "X-Ms-Token-Aad-Access-Token"
	EasyAuthIdTokenHeaderName       = "X-Ms-Token-Aad-Id-Token"
	PasswordCharacterSet            = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

//go:embed assets templates
var embedFS embed.FS

type Account struct {
	Password  string    `json:"password"`
	ExpiresOn time.Time `json:"expires_on"`
}

type App struct {
	Listen       string
	AuthURI      string
	UpstreamURI  string
	AccountDir   string
	AccountMap   *sync.Map
	ProxyHandler *httputil.ReverseProxy
	Template     *template.Template
}

func (app *App) GeneratePassphrase(n int) string {
	p := make([]byte, n)
	for i := 0; i < n; i++ {
		p[i] = PasswordCharacterSet[rand.Intn(len(PasswordCharacterSet))]
	}
	return string(p)
}

func (app *App) DebugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	e := os.Environ()
	sort.Slice(e, func(i, j int) bool { return e[i] < e[j] })
	for _, v := range e {
		fmt.Fprintln(w, v)
	}
}

func (app *App) EasyAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != app.AuthURI {
		sub, _ := fs.Sub(embedFS, "assets")
		http.StripPrefix(app.AuthURI, http.FileServer(http.FS(sub))).ServeHTTP(w, r)
		return
	}

	id := r.FormValue("id")
	if id == "" {
		id = r.Header.Get(EasyAuthPrincipalIdHeaderName)
	}
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	account, err := app.LoadAccount(id)
	if err != nil {
		account = &Account{}
	}
	account.ExpiresOn = time.Now().Add(7 * 24 * time.Hour)

	var password string
	if r.Method == http.MethodPost {
		password = app.GeneratePassphrase(32)
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		account.Password = string(hash)
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	data := struct{ AuthURI, Username, Password, ExpiresOn string }{
		AuthURI:   app.AuthURI,
		Username:  id,
		Password:  password,
		ExpiresOn: account.ExpiresOn.Format(time.RFC3339),
	}

	err = app.Template.Execute(w, data)
	if err != nil {
		log.Println(err)
	}
}

func (app *App) BasicAuth(user, pass string) bool {
	account, err := app.LoadAccount(user)
	if err != nil {
		return false
	}
	if account.ExpiresOn.Before(time.Now()) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(pass)) == nil
}

func (app *App) BasicAuthHandler(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	ok = ok && app.BasicAuth(user, pass)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	app.ProxyHandler.ServeHTTP(w, r)
}

func (app *App) StoreAccount(id string, account *Account) error {
	app.AccountMap.Store(id, account)
	b, err := json.Marshal(account)
	if err != nil {
		return err
	}
	path := filepath.Join(app.AccountDir, id)
	return os.WriteFile(path, b, 0600)
}

func (app *App) LoadAccount(id string) (*Account, error) {
	aany, ok := app.AccountMap.Load(id)
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
	err := os.Mkdir(app.AccountDir, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	files, err := os.ReadDir(app.AccountDir)
	if err != nil {
		return err
	}
	app.AccountMap = &sync.Map{}
	for _, file := range files {
		path := filepath.Join(app.AccountDir, file.Name())
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
		app.AccountMap.Store(file.Name(), account)
	}
	u, err := url.Parse(app.UpstreamURI)
	if err != nil {
		return err
	}
	app.ProxyHandler = httputil.NewSingleHostReverseProxy(u)
	app.Template, _ = template.New("index.html").ParseFS(embedFS, "templates/index.html")
	mux := http.NewServeMux()
	mux.Handle(filepath.Join(app.AuthURI, "assets")+"/", http.StripPrefix(app.AuthURI, http.FileServer(http.FS(embedFS))))
	mux.HandleFunc(app.AuthURI, app.EasyAuthHandler)
	mux.HandleFunc("/", app.BasicAuthHandler)
	return http.ListenAndServe(app.Listen, mux)
}

func main() {
	app := App{
		Listen:      os.Getenv(EnvListen),
		AuthURI:     os.Getenv(EnvAuthURI),
		UpstreamURI: os.Getenv(EnvUpstreamURI),
		AccountDir:  os.Getenv(EnvAccountDir),
		AccountMap:  &sync.Map{},
	}
	if app.Listen == "" {
		app.Listen = DefaultListen
	}
	if app.AuthURI == "" {
		app.AuthURI = DefaultAuthURI
	}
	if app.UpstreamURI == "" {
		app.UpstreamURI = DefaultUpstreamURI
	}
	if app.AccountDir == "" {
		app.AccountDir = DefaultAccountDir
	}
	err := app.Main(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
