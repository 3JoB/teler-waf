package teler

import (
	"github.com/3JoB/unsafeConvert"
	"github.com/savsgio/atreugo/v11"

	"github.com/valyala/fasttemplate"
)

// rejectHandler is default rejection handler
func rejectHandler(c *atreugo.RequestCtx) error {
	// Set Content-Type to text/html
	c.Response.Header.Set("Content-Type", "text/html")

	// Set the status code
	c.SetStatusCode(respStatus)

	// Set template interfaces

	data := map[string]any{
		// NOTE(dwisiswant0): Should we include *http.Request?
		"ID":      unsafeConvert.StringSlice(c.Response.Header.Peek(xTelerReqId)),
		"message": unsafeConvert.StringSlice(c.Response.Header.Peek(xTelerMsg)),
		"threat":  unsafeConvert.StringSlice(c.Response.Header.Peek(xTelerThreat)),
	}

	// Use custom response HTML page template if non-empty
	if customHTMLResponse != "" {
		respTemplate = customHTMLResponse
	}

	// Parse response template
	tpl := fasttemplate.New(respTemplate, "{{", "}}")

	// Write a response from the template
	// TODO(dwisiswant0): Add error handling here.
	_, _ = tpl.Execute(c.Response.BodyWriter(), data)
	return nil
}

// Handler implements the http.HandlerFunc for integration with the standard net/http library.
func (t *Teler) Handler(next atreugo.View) atreugo.View {
	return func(c *atreugo.RequestCtx) error {
		// Let teler analyze the request. If it returns an error,
		// that indicates the request should not continue.
		k, err := t.analyzeRequest(c)
		if err != nil {
			// Process the analyzeRequest
			t.postAnalyze(c, k, err)
			return nil
		}
		return next(c)
	}
}

// HandlerFuncWithNext is a special implementation for Negroni, but could be used elsewhere.
func (t *Teler) HandlerFuncWithNext(c *atreugo.RequestCtx, next atreugo.View) {
	// Let teler analyze the request. If it returns an error,
	// that indicates the request should not continue.
	k, err := t.analyzeRequest(c)
	if err != nil {
		// Process the analyzeRequest
		t.postAnalyze(c, k, err)
		return
	}
	// If next handler is not nil, call it.
	if next != nil {
		next(c)
	}
}
