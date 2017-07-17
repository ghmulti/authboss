// Package auth implements password based user logins.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"github.com/ghmulti/authboss"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"
)

func init() {
	authboss.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authboss.Authboss
}

// Initialize module
func (a *Auth) Initialize(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if a.Storer == nil && a.StoreMaker == nil {
		return errors.New("auth: Need a Storer")
	}

	if len(a.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if a.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	if  a.ResponseProcessor == nil {
		return errors.New("auth: Need response processor")
	}

	return nil
}

// Routes for the module
func (a *Auth) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/login":  a.loginHandlerFunc,
		"/logout": a.logoutHandlerFunc,
	}
}

// Storage requirements
func (a *Auth) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		a.PrimaryID:            authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{
			Id: authboss.ResponseIdLogin,
			Data: map[string]interface{}{
				"rememberme": a.IsLoaded("remember"),
				"recover":    a.IsLoaded("recover"),
				"register":   a.IsLoaded("register"),
				a.PrimaryID:  "*",
				"password":   "*",
			},
		})
	case methodPOST:
		key := r.FormValue(a.PrimaryID)
		password := r.FormValue("password")

		if valid, err := validateCredentials(ctx, key, password); err != nil {
			fmt.Fprintf(ctx.LogWriter, "auth: validate credentials failed: %v\n", err)
			procErr := authboss.ProcessingError{Name: "Internal server error", Code: http.StatusUnauthorized}
			return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLoginHandler, Error: &procErr})
		} else if !valid {
			if err := a.Callbacks.FireAfter(authboss.EventAuthFail, ctx); err != nil {
				fmt.Fprintf(ctx.LogWriter, "EventAuthFail callback error'd out: %v\n", err)
			}
			procErr := authboss.ProcessingError{Name: fmt.Sprintf("invalid %s and/or password", a.PrimaryID), Code: http.StatusUnauthorized}
			return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLoginHandler, Error: &procErr})
		}

		interrupted, err := a.Callbacks.FireBefore(authboss.EventAuth, ctx)
		if err != nil {
			return err
		} else if interrupted != authboss.InterruptNone {
			var reason string
			switch interrupted {
			case authboss.InterruptAccountLocked:
				reason = "Your account has been locked."
			case authboss.InterruptAccountNotConfirmed:
				reason = "Your account has not been confirmed."
			}
			procErr := authboss.ProcessingError{Name: reason, Code: http.StatusForbidden}
			return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLoginHandler, Error: &procErr})
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)
		ctx.Values = map[string]string{authboss.CookieRemember: r.FormValue(authboss.CookieRemember)}

		if err := a.Callbacks.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}

		return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLoginHandler})
	default:
		procErr := authboss.ProcessingError{Name: "Not supported", Code: http.StatusMethodNotAllowed}
		return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdError, Error: &procErr})
	}
}

func validateCredentials(ctx *authboss.Context, key, password string) (bool, error) {
	if err := ctx.LoadUser(key); err == authboss.ErrUserNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	actualPassword, err := ctx.User.StringErr(authboss.StorePassword)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

func (a *Auth) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)
		return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLogout})
	default:
		procErr := authboss.ProcessingError{Name: "Not supported", Code: http.StatusMethodNotAllowed}
		return a.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdLogout, Error: &procErr})
	}
}
