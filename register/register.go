// Package register allows for user registration.
package register

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"github.com/ghmulti/authboss"
)


// RegisterStorer must be implemented in order to satisfy the register module's
// storage requirments.
type RegisterStorer interface {
	authboss.Storer
	// Create is the same as put, except it refers to a non-existent key.  If the key is
	// found simply return authboss.ErrUserFound
	Create(key string, attr authboss.Attributes) error
}

func init() {
	authboss.RegisterModule("register", &Register{})
}

// Register module.
type Register struct {
	*authboss.Authboss
}

// Initialize the module.
func (r *Register) Initialize(ab *authboss.Authboss) (err error) {
	r.Authboss = ab

	if r.Storer != nil {
		if _, ok := r.Storer.(RegisterStorer); !ok {
			return errors.New("register: RegisterStorer required for register functionality")
		}
	} else if r.StoreMaker == nil {
		return errors.New("register: Need a RegisterStorer")
	}

	return nil
}

// Routes creates the routing table.
func (r *Register) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/register": r.registerHandler,
	}
}

// Storage returns storage requirements.
func (r *Register) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		r.PrimaryID:            authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (reg *Register) registerHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		fields := map[string]interface{}{
			reg.PrimaryID:     "*",
		}
		for _,v := range reg.ConfirmFields {
			fields[v] = "*"
		}
		return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{
			Id:   authboss.ResponseIdRegister,
			Data: fields,
		})
	case "POST":
		return reg.registerPostHandler(ctx, w, r)
	default:
		procErr := authboss.ProcessingError{Name: "Not supported", Code: http.StatusMethodNotAllowed}
		return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdError, Error: &procErr})
	}
}

func (reg *Register) registerPostHandler(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	key := r.FormValue(reg.PrimaryID)
	password := r.FormValue(authboss.StorePassword)

	validationErrs := authboss.Validate(r, reg.Policies, reg.ConfirmFields...)

	if user, err := ctx.Storer.Get(key); err != nil && err != authboss.ErrUserNotFound {
		return err
	} else if user != nil {
		validationErrs = append(validationErrs, authboss.FieldError{Name: reg.PrimaryID, Err: errors.New("Already in use")})
	}

	if len(validationErrs) != 0 {
		procErr := authboss.ProcessingError{Name: "Validation error", Code: http.StatusBadRequest, Data: validationErrs.Map()}
		return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdRegisterCallback, Error: &procErr})
	}

	attr, err := authboss.AttributesFromRequest(r) // Attributes from overriden forms
	if err != nil {
		return err
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), reg.BCryptCost)
	if err != nil {
		return err
	}

	attr[reg.PrimaryID] = key
	attr[authboss.StorePassword] = string(pass)
	ctx.User = attr

	if err := ctx.Storer.(RegisterStorer).Create(key, attr); err == authboss.ErrUserFound {
		procErr := authboss.ProcessingError{Name: "Already in use", Code: http.StatusBadRequest}
		return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdRegisterCallback, Error: &procErr})
	} else if err != nil {
		return err
	}

	if err := reg.Callbacks.FireAfter(authboss.EventRegister, ctx); err != nil {
		return err
	}

	if reg.IsLoaded("confirm") {
		status := map[string]interface{}{"status": "Account successfully created, please verify your e-mail address."}
		return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdRegisterCallback, Data: status})
	}

	ctx.SessionStorer.Put(authboss.SessionKey, key)

	status := map[string]interface{}{"status": "Account successfully created, you are now logged in."}
	return reg.ResponseProcessor(ctx, w, r, authboss.ResponseData{Id: authboss.ResponseIdRegisterCallback, Data: status})
}
