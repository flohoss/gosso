package gosso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v5"
)

func setupMountedRouter(t *testing.T, auth *Auth, register func(huma.API)) *echo.Echo {
	t.Helper()

	e := echo.New()
	e.Use(EchoContextMiddleware)

	config := huma.DefaultConfig("Test API", "test")
	config.OpenAPIPath = "/api/openapi"
	config.DocsPath = "/api/docs"
	config.SchemasPath = "/api/schemas"

	api := auth.Mount(e, config)
	register(api)

	return e
}

func serve(e *echo.Echo, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	return rec
}

func TestMount_AnswersNotFoundWhileDisabled(t *testing.T) {
	auth, err := New(Options{DB: newTestDB(t)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e := setupMountedRouter(t, auth, func(huma.API) {})

	for _, path := range []string{LoginRoute, CallbackRoute + "?code=x&state=y"} {
		if got := serve(e, http.MethodGet, path).Code; got != http.StatusNotFound {
			t.Errorf("%s = %d, want %d", path, got, http.StatusNotFound)
		}
	}
}

// Only routes registered on the returned API require a session; the lifecycle,
// the spec, the docs and the SPA shell stay reachable.
func TestMount_ProtectsOnlyTheMountedGroup(t *testing.T) {
	auth := newTestAuth(t)

	e := setupMountedRouter(t, auth, func(api huma.API) {
		huma.Register(api, huma.Operation{
			OperationID: "test-protected",
			Method:      http.MethodGet,
			Path:        "/api/protected",
		}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
			return nil, nil
		})
	})
	e.GET("/", func(c *echo.Context) error { return c.String(http.StatusOK, "shell") })

	cases := []struct {
		path string
		want int
	}{
		{path: "/api/protected", want: http.StatusFound},
		{path: "/api/openapi.json", want: http.StatusOK},
		{path: "/api/docs", want: http.StatusOK},
		{path: "/", want: http.StatusOK},
		{path: CallbackRoute + "?code=x&state=y", want: http.StatusFound},
	}

	for _, tc := range cases {
		if got := serve(e, http.MethodGet, tc.path).Code; got != tc.want {
			t.Errorf("%s = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func TestMount_ServesProtectedRouteWithASession(t *testing.T) {
	auth := newTestAuth(t)

	e := setupMountedRouter(t, auth, func(api huma.API) {
		huma.Register(api, huma.Operation{
			OperationID: "test-protected",
			Method:      http.MethodGet,
			Path:        "/api/protected",
		}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
			return nil, nil
		})
	})

	cookie := startTestSession(t, auth, "user-subject")

	if got := serve(e, http.MethodGet, "/api/protected", cookie).Code; got != http.StatusNoContent {
		t.Fatalf("/api/protected = %d, want %d", got, http.StatusNoContent)
	}
}

func TestMount_DocumentsTheSessionScheme(t *testing.T) {
	auth := newTestAuth(t)
	e := setupMountedRouter(t, auth, func(huma.API) {})

	spec := serve(e, http.MethodGet, "/api/openapi.json").Body.String()
	for _, expected := range []string{`"cookieAuth"`, `"in":"cookie"`, auth.SessionCookieName()} {
		if !strings.Contains(spec, expected) {
			t.Errorf("expected %q in the OpenAPI spec", expected)
		}
	}
}

func TestMount_ReportsTheCurrentUser(t *testing.T) {
	auth := newTestAuth(t)
	e := setupMountedRouter(t, auth, func(huma.API) {})

	if got := serve(e, http.MethodGet, MeRoute).Code; got != http.StatusOK {
		t.Fatalf("%s = %d, want %d", MeRoute, got, http.StatusOK)
	}

	cookie := startTestSession(t, auth, "user-subject")
	body := serve(e, http.MethodGet, MeRoute, cookie).Body.String()
	if !strings.Contains(body, `"authenticated":true`) {
		t.Fatalf("expected an authenticated payload, got %s", body)
	}
}

func TestMount_LogoutClearsTheSession(t *testing.T) {
	auth := newTestAuth(t)
	e := setupMountedRouter(t, auth, func(huma.API) {})

	cookie := startTestSession(t, auth, "user-subject")

	rec := serve(e, http.MethodPost, LogoutRoute, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s = %d, want %d", LogoutRoute, rec.Code, http.StatusOK)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, err := auth.Authenticate(echoContext(httptest.NewRecorder(), req)); err == nil {
		t.Fatal("expected the session to be revoked by the logout")
	}
}

func TestHandlers_RedirectToTheLoginPageOnFailure(t *testing.T) {
	auth := newTestAuth(t)
	e := setupMountedRouter(t, auth, func(huma.API) {})

	login := serve(e, http.MethodGet, LoginRoute)
	if login.Code != http.StatusFound {
		t.Fatalf("%s = %d, want %d", LoginRoute, login.Code, http.StatusFound)
	}
	if location := login.Header().Get(echo.HeaderLocation); location != LoginPageURL(LoginErrorUnavailable) {
		t.Fatalf("expected a %q redirect, got %q", LoginPageURL(LoginErrorUnavailable), location)
	}

	callback := serve(e, http.MethodGet, CallbackRoute+"?error=access_denied")
	if callback.Code != http.StatusFound {
		t.Fatalf("%s = %d, want %d", CallbackRoute, callback.Code, http.StatusFound)
	}
	if location := callback.Header().Get(echo.HeaderLocation); location != LoginPageURL(LoginErrorRejected) {
		t.Fatalf("expected a %q redirect, got %q", LoginPageURL(LoginErrorRejected), location)
	}
}

// The fake provider signs the id_token for any code and accepts the exchange,
// so the full browser handshake runs against the mounted router.
func TestHandlers_CompletesTheLoginAgainstTheFakeProvider(t *testing.T) {
	server := newFakeProvider(t)
	opts := testOptions()
	opts.IssuerURL = server.URL
	opts.DB = newTestDB(t)

	auth, err := New(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e := setupMountedRouter(t, auth, func(huma.API) {})

	login := serve(e, http.MethodGet, LoginRoute)
	if login.Code != http.StatusFound {
		t.Fatalf("%s = %d, want %d", LoginRoute, login.Code, http.StatusFound)
	}

	stateCookie := stateCookieOf(t, login.Result().Cookies(), auth)
	if stateCookie == nil {
		t.Fatal("expected a state cookie")
	}
	state := strings.Split(stateCookie.Value, stateSeparator)[0]

	callback := serve(e, http.MethodGet, CallbackRoute+"?code=user-123&state="+state, stateCookie)
	if callback.Code != http.StatusFound {
		t.Fatalf("%s = %d, want %d", CallbackRoute, callback.Code, http.StatusFound)
	}
	if location := callback.Header().Get(echo.HeaderLocation); location != "/" {
		t.Fatalf("expected a redirect to %q, got %q", "/", location)
	}

	session := sessionCookieOf(t, callback.Result().Cookies(), auth)
	if session == nil {
		t.Fatal("expected a session cookie after the callback")
	}

	if got := serve(e, http.MethodGet, MeRoute, session).Body.String(); !strings.Contains(got, `"authenticated":true`) {
		t.Fatalf("expected an authenticated me payload after the handshake, got %s", got)
	}
}

func TestMeHandler_ReportsDisabledAuth(t *testing.T) {
	auth, err := New(Options{DB: newTestDB(t)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	e := setupMountedRouter(t, auth, func(huma.API) {})

	if got := serve(e, http.MethodGet, MeRoute).Body.String(); !strings.Contains(got, `"auth_enabled":false`) {
		t.Fatalf("expected a disabled payload, got %s", got)
	}
}

func TestMount_FillsAnEmptyHumaConfig(t *testing.T) {
	auth := newTestAuth(t)

	e := echo.New()
	e.Use(EchoContextMiddleware)

	api := auth.Mount(e, huma.Config{OpenAPI: &huma.OpenAPI{}})
	huma.Register(api, huma.Operation{OperationID: "test", Method: http.MethodGet, Path: "/api/x"}, func(context.Context, *struct{}) (*struct{}, error) {
		return nil, nil
	})

	scheme := api.OpenAPI().Components.SecuritySchemes[SecurityScheme]
	if scheme == nil || scheme.In != "cookie" || scheme.Name != auth.SessionCookieName() {
		t.Fatalf("expected a cookie scheme for %q, got %+v", SecurityScheme, scheme)
	}
}

func TestMount_NilsTheHumaConfigDefaults(t *testing.T) {
	auth := newTestAuth(t)

	e := echo.New()
	e.Use(EchoContextMiddleware)

	auth.Mount(e, huma.Config{OpenAPIPath: "/api/openapi"})

	// A config without a prepared OpenAPI document still mounts and serves the spec.
	if got := serve(e, http.MethodGet, "/api/openapi.json").Code; got != http.StatusOK {
		t.Fatalf("expected the spec to be served, got %d", got)
	}
}
