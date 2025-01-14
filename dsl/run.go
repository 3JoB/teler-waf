// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package dsl

import (
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/samber/lo"

	"github.com/3JoB/teler-waf/threat"
)

// Run executes the provided expr.Program in the DSL environment.
func (e *Env) Run(program *vm.Program) (any, error) {
	// Lock
	e.sl.Lock()
	defer e.sl.Unlock()

	// If the Threat field in the environment is defined, assign it to the "threat" function in the environment.
	if e.Threat != threat.Undefined {
		e.vars["threat"] = e.Threat
	}

	// Combine all requests
	e.Requests["ALL"] = lo.MapToSlice(e.Requests, func(k string, v any) string {
		if s, ok := v.(string); ok && s != "" {
			return s
		}

		return ""
	})

	// Assign the Requests map to the "request" variable in the environment.
	e.vars["request"] = e.Requests

	// Merge maps of variables and functions
	envMaps := lo.Assign[string, any](e.vars, e.funcs)

	// Run the provided program using the merged environments.
	out, err := expr.Run(program, envMaps)
	if err != nil {
		return nil, err
	}

	// Return the output.
	return out, nil
}
