// Copyright Dwi Siswanto and/or licensed to Dwi Siswanto under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
// See the LICENSE-ELASTIC file in the project root for more information.

package option

import (
	"fmt"
	"os"

	"github.com/goccy/go-json"
	"gopkg.in/yaml.v3"

	"github.com/3JoB/teler-waf"
)

func readFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf(errNotRegularFile, path)
	}

	return os.ReadFile(path)
}

func unmarshalJSONBytes(raw []byte) (teler.Options, error) {
	// Unmarshal the JSON into the Options struct
	err := json.Unmarshal(raw, &opt)
	return opt, err
}

func unmarshalYAMLBytes(raw []byte) (teler.Options, error) {
	// Unmarshal the JSON into the Options struct
	err := yaml.Unmarshal(raw, &opt)
	return opt, err
}
