package teler

import (
	"errors"
	"html"
	"strings"

	realip "github.com/3JoB/atreugo-realip"
	"github.com/3JoB/unsafeConvert"
	"github.com/antonmedv/expr/vm"
	"github.com/patrickmn/go-cache"
	"github.com/savsgio/atreugo/v11"
	"github.com/twharmon/gouid"
	"gitlab.com/golang-commonmark/mdurl"

	"github.com/3JoB/teler-waf/request"
	"github.com/3JoB/teler-waf/threat"
)

// inThreatIndex checks if the given substring is in specific threat datasets
func (t *Teler) inThreatIndex(kind threat.Threat, substr string) bool {
	if i := strings.Index(t.threat.data[kind], substr); i >= 0 {
		return true
	}

	return false
}

// setDSLRequestEnv will set DSL environment based on the incoming request information.
func (t *Teler) setDSLRequestEnv(c *atreugo.RequestCtx) {
	// Converts map of headers to RAW string
	headers := headersToRawString(c)

	// Decode the URL-encoded and unescape HTML entities request URI of the URL
	uri := stringDeUnescape(unsafeConvert.StringSlice(c.RequestURI()))

	// Declare byte slice for request body.
	var body string

	// Check if the request has a body
	if c.Request.Body() != nil {
		// Decode the URL-encoded and unescape HTML entities of body
		body = stringDeUnescape(unsafeConvert.StringSlice(c.Request.Body()))
	}

	// Set DSL requests environment
	t.env.Requests = map[string]any{
		"URI":     uri,
		"Headers": headers,
		"Body":    body,
		"Method":  unsafeConvert.StringSlice(c.Method()),
		"Remote":  unsafeConvert.StringSlice(c.Request.Header.Peek("Remote-Host")),
		"IP":      realip.FromRequest(c),
	}

	if (t.opt.MaxMind != MaxMind{}) {
		if t.opt.MaxMind.Install {
			asn, city := t.setMmdb(c)
			if city != nil {
				t.env.Requests["DB"] = map[string]any{
					"City":    city.City.Names,
					"Country": city.Country,
					"Continent": city.Continent,
					"ASN": map[string]any{
						"Code": asn.AutonomousSystemNumber,
						"Org":  asn.AutonomousSystemOrganization,
					},
				}
			}
		}
	}
}

// headersToRawString converts a map of http.Header to
// multiline string, example:
// from,
//
//	Header = map[string][]string{
//		"Accept-Encoding": {"gzip, deflate"},
//		"Accept-Language": {"en-us"},
//		"Foo": {"Bar", "two"},
//	}
//
// to
//
//	Host: example.com
//	accept-encoding: gzip, deflate
//	Accept-Language: en-us
//	fOO: Bar
//	foo: two
func headersToRawString(c *atreugo.RequestCtx) string {
	return unsafeConvert.StringSlice(c.Request.Header.Header())
}

// unescapeHTML to unescapes any HTML entities, i.e. &aacute;"
// unescapes to "á", as does "&#225;" and "&#xE1;".
func unescapeHTML(s string) string {
	return html.UnescapeString(s)
}

// toURLDecode decode URL-decoded characters string using mdurl
func toURLDecode(s string) string {
	return mdurl.Decode(s)
}

// stringDeUnescape to decode URL-decoded characters, and
// unescapes any HTML entities
func stringDeUnescape(s string) string {
	s = toURLDecode(s)
	return unescapeHTML(s)
}

// isValidMethod check if the given request.Method is valid
func isValidMethod(method request.Method) bool {
	switch method {
	case request.GET, request.HEAD, request.POST, request.PUT, request.PATCH:
	case request.DELETE, request.CONNECT, request.OPTIONS, request.TRACE, request.ALL:
	case "":
		return true
	}

	return false
}

// normalizeRawStringReader trim double-quotes of HTTP raw string,
// replace double-escape of CR and LF, and double it in the end, and
// returning as pointer of strings.Reader
func normalizeRawStringReader(raw string) *strings.Reader {
	var builder strings.Builder

	raw = strings.Trim(raw, `"`)
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	builder.WriteString(raw)
	builder.WriteString("\r\n\r\n")

	return strings.NewReader(builder.String())
}

// setCustomHeader such as message and threat category to the header response
func setCustomHeaders(c *atreugo.RequestCtx, msg string, cat threat.Threat) {
	// Set the "X-Teler-Msg" and "X-Teler-Threat" header in the response
	c.Response.Header.Set(xTelerMsg, msg)
	c.Response.Header.Set(xTelerThreat, cat.String())
}

// setReqIdHeader to set teler request ID header response
func setReqIdHeader(c *atreugo.RequestCtx) string {
	// Generate a unique ID using the gouid package.
	id := gouid.Bytes(10)

	// Set the "X-Teler-Req-Id" header in the response with the unique ID.
	c.Response.Header.Set(xTelerReqId, id.String())
	return id.String()
}

// removeSpecialChars to remove special characters with empty string
// includes line feed/newline, horizontal tab, backspace & form feed
func removeSpecialChars(str string) string {
	str = strings.ReplaceAll(str, "\n", "") // Replace all newline
	str = strings.ReplaceAll(str, "\r", "") // Replace all carriage return
	str = strings.ReplaceAll(str, "\t", "") // Replace all horizontal tab
	str = strings.ReplaceAll(str, "\b", "") // Replace all backspace
	str = strings.ReplaceAll(str, "\f", "") // Replace all form feed

	return str
}

// getCache returns the cached error value for the given key.
// If the key is not found in the cache or the value is nil, it returns nil, false.
// When development flag is not set it will always return nil, false
func (t *Teler) getCache(key string) (error, bool) {
	if t.opt.Development {
		return nil, false
	}

	if msg, ok := t.cache.Get(key); ok {
		if msg == nil {
			return nil, ok
		}

		return msg.(error), ok
	}

	return nil, false
}

// setCache sets the error value for the given key in the cache.
// if msg is empty it sets a nil error, otherwise it creates a new error with the msg.
// When development flag is not set it will return without setting anything in the cache
func (t *Teler) setCache(key string, msg string) {
	if t.opt.Development {
		return
	}

	var err error

	if msg != "" {
		err = errors.New(msg)
	} else {
		err = nil
	}

	t.cache.Set(key, err, cache.DefaultExpiration)
}

// isDSLProgramTrue checks if the given compiled DSL expression (program) is true.
func (t *Teler) isDSLProgramTrue(program *vm.Program) bool {
	dslEval, err := t.env.Run(program)
	if err != nil {
		return false
	}

	return dslEval.(bool)
}

// setCache sets the error message to logs.
//
// 0 is Error, 1 is Panic
func (t *Teler) error(level int, msg string) {
	// log := t.log.WithOptions(zap.WithCaller(true), zap.AddCallerSkip(1))

	switch level {
	case 0:
		t.log.Error().Msg(msg)
	case 1:
		t.log.Panic().Msg(msg)
		// case zapcore.FatalLevel:
		// 	log.Fatal(msg)
	}
}
