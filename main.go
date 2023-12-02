package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	EnvUpstream                   = "APP_UPSTREAM"
	EnvListen                     = "APP_LISTEN"
	EnvStorePath                  = "APP_STORE_PATH"
	DefaultUpstream               = "http://127.0.0.1:5000"
	DefaultListen                 = ":8080"
	DefaultStorePath              = "store"
	EasyAuthPrincipalHeaderName   = "X-Ms-Client-Principal"
	EasyAuthPrincipalIdHeaderName = "X-Ms-Client-Principal-Id"
	EasyAuthAccessTokenHeaderName = "X-Ms-Token-Aad-Access-Token"
	EasyAuthIdTokenHeaderName     = "X-Ms-Token-Aad-Id-Token"
	PassphraseCharacterSet        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

type Account struct {
	Password  string    `json:"password"`
	ExpiresOn time.Time `json:"expires_on"`
}

type App struct {
	Upstream     string
	Listen       string
	StorePath    string
	AccountList  *sync.Map
	ProxyHandler *httputil.ReverseProxy
}

func (app *App) GeneratePassphrase(n int) string {
	p := make([]byte, n)
	for i := 0; i < n; i++ {
		p[i] = PassphraseCharacterSet[rand.Intn(len(PassphraseCharacterSet))]
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
	id := r.Header.Get(EasyAuthPrincipalIdHeaderName)
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p := app.GeneratePassphrase(32)
	hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	account := &Account{
		Password:  string(hash),
		ExpiresOn: time.Now().Add(7 * 24 * time.Hour),
	}
	app.StoreAccount(id, account)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User: %s\nPass: %s\n", id, p)
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
	app.AccountList.Store(id, account)
	b, err := json.Marshal(account)
	if err != nil {
		return err
	}
	path := filepath.Join(app.StorePath, id)
	return os.WriteFile(path, b, 0600)
}

func (app *App) LoadAccount(id string) (*Account, error) {
	aany, ok := app.AccountList.Load(id)
	if !ok {
		return nil, fmt.Errorf("account not found")
	}
	account, ok := aany.(*Account)
	if !ok {
		return nil, fmt.Errorf("account not found")
	}
	return account, nil
}

func (app *App) Initialize() error {
	err := os.Mkdir(app.StorePath, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}
	app.AccountList = &sync.Map{}
	files, err := os.ReadDir(app.StorePath)
	if err != nil {
		return err
	}
	for _, file := range files {
		path := filepath.Join(app.StorePath, file.Name())
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
		app.AccountList.Store(file.Name(), account)
	}
	return nil
}

func (app *App) Main(ctx context.Context) error {
	err := app.Initialize()
	if err != nil {
		return err
	}
	u, err := url.Parse(app.Upstream)
	if err != nil {
		return err
	}
	app.ProxyHandler = httputil.NewSingleHostReverseProxy(u)
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/", app.EasyAuthHandler)
	mux.HandleFunc("/", app.BasicAuthHandler)
	return http.ListenAndServe(app.Listen, mux)
}

func main() {
	app := App{
		Upstream:    os.Getenv(EnvUpstream),
		Listen:      os.Getenv(EnvListen),
		StorePath:   os.Getenv(EnvStorePath),
		AccountList: &sync.Map{},
	}
	if app.Upstream == "" {
		app.Upstream = DefaultUpstream
	}
	if app.Listen == "" {
		app.Listen = DefaultListen
	}
	if app.StorePath == "" {
		app.StorePath = DefaultStorePath
	}
	err := app.Main(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
