package authboss

import (
	"net/http"
)

const (
	ResponseIdLogin 				  = "ResponseIdLogin"
	ResponseIdLoginHandler            = "ResponseIdLoginHandler"
	ResponseIdLogout                  = "ResponseIdLogout"
	ResponseIdConfirm                 = "ResponseIdConfirm"
	ResponseIdOAuth2                  = "ResponseIdOAuth2"
	ResponseIdOAuth2Callback          = "ResponseIdOAuth2Callback"
	ResponseIdOAuth2Logout            = "ResponseIdOAuth2Logout"
	ResponseIdRecover                 = "ResponseIdRecover"
	ResponseIdRecoverCallback         = "ResponseIdRecoverCallback"
	ResponseIdRecoverComplete         = "ResponseIdRecoverComplete"
	ResponseIdRecoverCompleteCallback = "ResponseIdRecoverCompleteCallback"
	ResponseIdRegister                = "ResponseIdRegister"
	ResponseIdRegisterCallback        = "ResponseIdRegisterCallback"
	ResponseIdError                   = "ResponseIdError"
)

type ResponseProcessor func(ctx *Context, w http.ResponseWriter, r *http.Request, data *ResponseData) error

// ResponseData is used to render templates with.
type ResponseData struct {
	Id string
	Error *ProcessingError
	Data map[string]interface{}
}

// ViewDataMaker asks for an HTMLData object to assist with rendering.
type ViewDataMaker func(http.ResponseWriter, *http.Request) HTMLData

// HTMLData is used to render templates with.
type HTMLData map[string]interface{}

// NewHTMLData creates HTMLData from key-value pairs. The input is a key-value
// slice, where odd elements are keys, and the following even element is their value.
func NewHTMLData(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	h := make(HTMLData)

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}

// Merge adds the data from other to h. If there are conflicting keys
// they are overwritten by other's values.
func (h HTMLData) Merge(other HTMLData) HTMLData {
	for k, v := range other {
		h[k] = v
	}
	return h
}

// MergeKV adds extra key-values to the HTMLData. The input is a key-value
// slice, where odd elements are keys, and the following even element is their value.
func (h HTMLData) MergeKV(data ...interface{}) HTMLData {
	if len(data)%2 != 0 {
		panic("It should be a key value list of arguments.")
	}

	for i := 0; i < len(data)-1; i += 2 {
		k, ok := data[i].(string)
		if !ok {
			panic("Keys must be strings.")
		}

		h[k] = data[i+1]
	}

	return h
}
