// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package teler

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/3JoB/unsafeConvert"
	"github.com/dlclark/regexp2"
	"github.com/grafana/regexp"
	"github.com/savsgio/atreugo/v11"
	"golang.org/x/net/publicsuffix"

	"github.com/3JoB/teler-waf/request"
	"github.com/3JoB/teler-waf/threat"
)

// Analyze runs the actual checks.
func (t *Teler) Analyze(c *atreugo.RequestCtx) error {
	_, err := t.analyzeRequest(c)

	// If threat detected, set teler request ID to the header
	if err != nil {
		setReqIdHeader(c)
	}

	return err
}

func (t *Teler) setMmdb(c *atreugo.RequestCtx) (*ASN, *City) {
	// Get the client's IP address
	clientIP := t.env.GetRequestValue("IP")

	// Check if the client's IP address is in the cache
	if _, ok := t.getCache(clientIP); ok {
		return nil, nil
	}

	if (t.opt.MaxMind != MaxMind{}) {
		if t.opt.MaxMind.Install {
			nip := net.ParseIP(clientIP)

			var (
				asn  ASN
				city City
			)

			t.threat.MaxM.City.Lookup(nip, &city)
			t.threat.MaxM.ASN.Lookup(nip, &asn)
			return &asn, &city
			// They are temporary Debug methods and will be removed soon.
			// t.log.Info().Any("ASN", asn).Msg("asn msg")
			// t.log.Info().Any("City", city).Msg("city msg")
		}
	}
	return nil, nil
}

/*
analyzeRequest checks an incoming HTTP request for certain types of threats or vulnerabilities.
If a threat is detected, the function returns an error and the request is stopped from continuing through the middleware chain.

The function takes in two arguments: a http.ResponseWriter and an http.Request.
It returns a threat type and an error value.

The function first checks the request against any custom rules defined in the Teler struct.
If a custom rule is violated, the function returns an error with the name of the violated rule as the message.
If no custom rules are violated, the function continues processing.

The function then checks whether the request URI, headers, or client IP address are included
in a whitelist of patterns. If any of those values are in the whitelist, the function returns early.

The function then retrieves the threat struct from the Teler struct.
It iterates over the elements in the excludes map of the threat struct.
For each element in the excludes map, the function checks whether the value is true.
If it is true, the loop continues to the next iteration.
Otherwise, the function performs a check based on the type of threat specified by the key in the excludes map.

The types of threats that are checked for are:

- Common web attacks
- Common Vulnerabilities and Exposures (CVEs)
- Bad IP addresses
- Bad referrers
- Bad crawlers
- Directory bruteforce attacks
*/
func (t *Teler) analyzeRequest(c *atreugo.RequestCtx) (threat.Threat, error) {
	var err error

	// Initialize DSL requests environment
	t.setDSLRequestEnv(c)

	// Check the request against custom rules
	if err := t.checkCustomRules(c); err != nil {
		return threat.Custom, err
	}

	// Retrieve the threat struct from the Teler struct
	th := t.threat

	// Iterate over the excludes map in the threat struct
	for k, v := range th.excludes {
		// If the value in the excludes map is true, skip to the next iteration
		if v {
			continue
		}

		// Set DSL threat environment
		t.env.Threat = k

		// Check for the threat type specified by the key in the excludes map
		switch k {
		case threat.CommonWebAttack:
			err = t.checkCommonWebAttack(c) // Check for common web attacks
		case threat.CVE:
			err = t.checkCVE(c) // Check for Common Vulnerabilities and Exposures (CVEs)
		case threat.BadIPAddress:
			err = t.checkBadIPAddress() // Check for bad IP addresses
		case threat.BadReferrer:
			err = t.checkBadReferrer(c) // Check for bad referrers
		case threat.BadCrawler:
			err = t.checkBadCrawler(c) // Check for bad crawlers
		case threat.DirectoryBruteforce:
			err = t.checkDirectoryBruteforce(c) // Check for directory bruteforce attacks
		}

		// If a threat is detected, return the threat type and an error
		if err != nil {
			return k, err
		}
	}

	// If no threats are detected, return Undefined and a nil error
	return threat.Undefined, nil
}

// checkCustomRules checks the given http.Request against a set of custom rules defined in the Teler struct.
// If any of the custom rules are violated, the function returns an error with the name of the violated rule as the message.
// If no custom rules are violated, the function returns nil.
func (t *Teler) checkCustomRules(c *atreugo.RequestCtx) error {
	// Declare headers, URI, and body of a request.
	headers := t.env.GetRequestValue("Headers")
	uri := t.env.GetRequestValue("URI")
	body := t.env.GetRequestValue("Body")

	// Check if the request is in cache
	key := headers + uri + body
	if err, ok := t.getCache(key); ok {
		return err
	}

	// Iterate over the Customs field of the Teler struct, which is a slice of custom rules
	for _, rule := range t.opt.Customs {
		// Initialize the found match counter to zero
		f := 0

		// Iterate over the Rules field of the current custom rule, which is a slice of rule conditions
		for _, cond := range rule.Rules {
			ok := false

			// Check if DSL expression is not empty, then evaluate the program
			if cond.DSL != "" {
				ok = t.isDSLProgramTrue(cond.dslProgram)
			}

			// Returns early if the DSL expression above is match.
			if ok {
				t.setCache(key, rule.Name)
				return errors.New(rule.Name)
			}

			// Check if the Method field of the current rule condition matches the request method
			// If the Method field is ALL, match any request method
			switch {
			case cond.Method == request.ALL:
				ok = true
			case string(cond.Method) == unsafeConvert.StringSlice(c.Method()):
				ok = true
			}

			// If the request method doesn't match, skip the current rule condition
			if !ok {
				break
			}

			ok = false

			// Get the compiled regex pattern for the current rule condition
			pattern := cond.patternRegex

			// Check if the Element field of the current rule condition matches the request URI, headers, body, or any of them
			// If it matches, set ok to true
			switch cond.Element {
			case request.URI:
				ok = pattern.MatchString(uri)
			case request.Headers:
				ok = pattern.MatchString(headers)
			case request.Body:
				ok = pattern.MatchString(body)
			case request.Any:
				ok = (pattern.MatchString(uri) || pattern.MatchString(headers) || pattern.MatchString(body))
			}

			// If the rule condition is satisfied, increment the found match counter
			if ok {
				// If the rule condition "or", cache the request and return an error with
				// the Name field of the custom rule as the message.
				// If the rule condition is "and", increment the found match counter
				switch rule.Condition {
				case "or":
					t.setCache(key, rule.Name)
					return errors.New(rule.Name)
				case "and":
					f++
				}
			}
		}

		// If the rule condition is "and", and number of found matches is equal to the number of rule conditions,
		// cache the request and return an error with the Name field of the custom rule as the message
		if rule.Condition == "and" && f >= len(rule.Rules) {
			t.setCache(key, rule.Name)
			return errors.New(rule.Name)
		}
	}

	// Cache the request
	t.setCache(key, "")

	// If no custom rules were violated, return nil
	return nil
}

// checkCommonWebAttack checks if the request contains any patterns that match the common web attacks data.
// If a match is found, it returns an error indicating a common web attack has been detected.
// If no match is found, it returns nil.
func (t *Teler) checkCommonWebAttack(c *atreugo.RequestCtx) error {
	// Decode the URL-encoded and unescape HTML entities in the
	// request URI of the URL then remove all special characters
	uri := removeSpecialChars(stringDeUnescape(unsafeConvert.StringSlice(c.URI().FullURI())))

	// Declare body of request then remove all special characters
	body := removeSpecialChars(t.env.GetRequestValue("Body"))

	// Check if the request is in cache
	key := uri + body
	if err, ok := t.getCache(key); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Iterate over the filters in the CommonWebAttack data stored in the t.threat.cwa.Filters field
	for _, filter := range t.threat.cwa.Filters {
		// Initialize a variable to track whether a match is found
		var match bool

		// Check the type of the filter's pattern
		switch pattern := filter.pattern.(type) {
		case *regexp.Regexp: // If the pattern is a regex
			match = pattern.MatchString(uri) || pattern.MatchString(body)
		case *regexp2.Regexp: // If the pattern is a regex2 expr
			d, _ := pattern.MatchString(uri)
			p, _ := pattern.MatchString(body)
			match = d || p
		default: // If the pattern is of an unknown type, skip to the next iteration
			continue
		}

		// If the pattern matches the request URI or body, cache the request
		// and return an error indicating a common web attack has been detected
		if match {
			t.setCache(key, filter.Description)
			return errors.New(filter.Description)
		}
	}

	// Cache the request
	t.setCache(key, "")

	// Return nil if no match is found
	return nil
}

// checkCVE checks the request against a set of templates to see if it matches a known
// Common Vulnerabilities and Exposures (CVE) threat.
// It takes a pointer to an HTTP request as an input and returns an error if the request
// matches a known threat. Otherwise, it returns nil.
func (t *Teler) checkCVE(c *atreugo.RequestCtx) error {
	// data is the set of templates to check against.
	cveData := t.threat.cve

	// kind is the type of template to check (either "path" or "raw").
	var kind string

	// requestParams is a map that stores the query parameters of the request URI and
	// iterate over the query parameters of the request URI and add them to the map.
	requestParams := make(map[string]string)

	prul, err := url.Parse(unsafeConvert.StringSlice(c.URI().FullURI()))
	if err != nil {
		return err
	}
	for q, v := range prul.Query() {
		requestParams[q] = v[0]
	}

	key := fmt.Sprintf("%v", requestParams)
	if err, ok := t.getCache(key); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Iterate over the templates in the data set.
	for _, cveTemplate := range cveData.GetArray("templates") {
		// ID is the current CVE ID of the templates
		cveID := unsafeConvert.StringSlice(cveTemplate.GetStringBytes("id"))

		// Iterate over the requests in the template.
		for _, request := range cveTemplate.GetArray("requests") {
			// Determine the kind of template (either "path" or "raw").
			switch {
			case len(request.GetArray("path")) > 0:
				kind = "path"
			case len(request.GetArray("raw")) > 0:
				kind = "raw"
			}

			// If the template is a "path" type and the request method doesn't match, skip this template.
			if kind == "path" && unsafeConvert.StringSlice(request.GetStringBytes("method")) != unsafeConvert.StringSlice(c.Method()) {
				continue
			}

			// Iterate over the CVE URLs
			for _, cve := range cveURL[cveID] {
				// If the CVE path is empty or contains only a single character, skip this CVE URL.
				if len(cve.Path) <= 1 {
					continue
				}

				// If the request path doesn't match the CVE path, skip this CVE URL.

				if unsafeConvert.StringSlice(c.URI().Path()) != cve.Path {
					continue
				}

				// diffParams is a map that stores the query parameters of the CVE URI and iterate over the
				// query parameters of the CVE URI and add them to the diffParams map.
				diffParams := make(map[string]string)
				for q, v := range cve.Query() {
					diffParams[q] = v[0]
				}

				// allParamsMatch is a flag that indicates whether all the query parameters in the CVE URI are
				// present in the request URI and iterate over the query parameters of the CVE URI.
				allParamsMatch := true
				for q, v := range diffParams {
					// If a query parameter in the CVE URI is not present in the request URI,
					// set allParamsMatch to false and break out of the loop.
					if requestParams[q] != v {
						allParamsMatch = false
						break
					}
				}

				// If all the query parameters in the CVE URI are present in the request URI,
				// cache the request and return an error of CVE ID.
				if allParamsMatch {
					t.setCache(key, cveID)
					return errors.New(cveID)
				}
			}
		}
	}

	// Cache the request
	t.setCache(key, "")

	// Return nil if the request doesn't match any known threat.
	return nil
}

// checkBadIPAddress checks if the client IP address is in the BadIPAddress index.
// It returns an error if the client IP address is found in the index, indicating a bad IP address.
// Otherwise, it returns nil.
func (t *Teler) checkBadIPAddress() error {
	// Get the client's IP address
	clientIP := t.env.GetRequestValue("IP")

	// Check if the client's IP address is in the cache
	if err, ok := t.getCache(clientIP); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Check if the client IP address is in BadIPAddress index
	if t.inThreatIndex(threat.BadIPAddress, clientIP) {
		// Cache the client's IP address and return an error
		// indicating a bad IP address has been detected
		t.setCache(clientIP, errBadIPAddress)
		return errors.New(errBadIPAddress)
	}

	// Cache the client's IP address
	t.setCache(clientIP, "")

	// Return nil if the remote address is not found in the index
	return nil
}

// It does this by parsing and validate the referer URL, and then finding the effective
// top-level domain plus one. The resulting domain is then checked against the BadReferrer
// index in the threat struct. If the domain is found in the index, an error indicating a
// bad HTTP referer is returned. Otherwise, nil is returned.
func (t *Teler) checkBadReferrer(c *atreugo.RequestCtx) error {
	// Parse the request referer URL

	valid, ref, err := isValidReferrer(unsafeConvert.StringSlice(c.Referer()))
	if err != nil {
		t.error(0, err.Error())
		return nil
	}

	// Return early if TLD hostname is invalid
	if !valid {
		return nil
	}

	// Extract the effective top-level domain plus one from the hostname of the referer URL
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(ref)
	if err != nil {
		t.error(0, err.Error())
		return nil
	}

	// Check if the referrer request is in cache
	if err, ok := t.getCache(eTLD1); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Check if the root domain of request referer header is in the BadReferrer index
	if t.inThreatIndex(threat.BadReferrer, eTLD1) {
		// If the domain is found in the index, cache the referrer
		// request and return an error indicating a bad HTTP referer
		t.setCache(eTLD1, errBadIPAddress)
		return errors.New(errBadReferer)
	}

	// Cache the referrer of the request
	t.setCache(eTLD1, "")

	// Return nil if no match is found in the BadReferrer index
	return nil
}

// checkBadCrawler checks the request for bad crawler activity.
// It retrieves the User-Agent from the request and iterates over
// the compiled regular expressions in the badCrawler field of the threat struct.
// If any of the regular expressions match the User-Agent,
// it returns an error with the message "bad crawler".
// If the User-Agent is empty or no regular expressions match,
// it returns nil.
func (t *Teler) checkBadCrawler(c *atreugo.RequestCtx) error {
	// Retrieve the User-Agent from the request
	ua := unsafeConvert.StringSlice(c.UserAgent())

	// Do not process the check if User-Agent is empty
	if ua == "" {
		return nil
	}

	// Check if the referrer request is in cache
	if err, ok := t.getCache(ua); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Iterate over BadCrawler compiled patterns and do the check
	for _, pattern := range t.threat.badCrawler {
		// Initialize a variable to track whether a match is found
		var match bool

		// Check the type of the pattern
		switch p := pattern.(type) {
		case *regexp.Regexp: // If the pattern is a regex
			match = p.MatchString(ua)
		default: // If the pattern is of an unknown type, skip to the next iteration
			continue
		}

		// Check if the pattern is not nil and matches the User-Agent,
		// cache the User-Agent if it matched
		if match {
			t.setCache(ua, errBadCrawler)
			return errors.New(errBadCrawler)
		}
	}

	// Cache the User-Agent of the request
	t.setCache(ua, "")

	return nil
}

// checkDirectoryBruteforce checks the request for a directory bruteforce attack.
// It checks if the pattern matches the data using regexp.MatchString. If a match
// is found, it returns an error indicating a directory bruteforce attack has been
// detected. If no match is found or there was an error during the regex matching
// process, it returns nil.
func (t *Teler) checkDirectoryBruteforce(c *atreugo.RequestCtx) error {
	// Trim the leading slash from the request path, and if path
	// is empty string after the trim, do not process the check
	path := strings.TrimLeft(unsafeConvert.StringSlice(c.URI().Path()), "/")
	if path == "" {
		return nil
	}

	// Check if the request path is in cache
	if err, ok := t.getCache(path); ok {
		return err
	}

	// Check if the requestis in whitelists
	// and return it immediately
	for _, wl := range t.wlPrograms {
		if t.isDSLProgramTrue(wl) {
			return nil
		}
	}

	// Create a regex pattern that matches the entire request path
	pattern := fmt.Sprintf("(?m)^%s$", regexp.QuoteMeta(path))

	// Check if the pattern matches the data using regexp.MatchString
	match, err := regexp.MatchString(pattern, t.threat.data[threat.DirectoryBruteforce])
	if err != nil {
		// Logs and return nil if there was an error during the regex matching process
		t.error(0, err.Error())
		return nil
	}

	// If the pattern matches the data, cache the request path and
	// return an error indicating a directory bruteforce attack has been detected
	if match {
		t.setCache(path, errDirectoryBruteforce)
		return errors.New(errDirectoryBruteforce)
	}

	// Cache the request path
	t.setCache(path, "")

	// Return nil if no match is found
	return nil
}
