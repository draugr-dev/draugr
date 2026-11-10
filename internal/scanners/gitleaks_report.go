package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// walkGitleaksResults reads a Gitleaks SARIF report one result at a time, handing each to visit in
// the order the report holds them. A history pass's report runs to gigabytes, nearly all of it
// results, and what this holds at once is one of them.
//
// A report or a run that is not an object, and runs or results that are not a list, are an error,
// as they are to decoding the report into its runs and their results. A report or a run given as
// null holds no results. So does a member given as null. A report naming its runs twice, or a run
// its results, is an error too: decoding it whole keeps only the last, and a walk would count both.
// Nothing after the report is read.
func walkGitleaksResults(r io.Reader, visit func(json.RawMessage) error) error {
	dec := json.NewDecoder(r)
	return walkJSONObject(dec, "the report", func(key string) (bool, error) {
		if key != "runs" {
			return false, nil
		}
		return true, walkJSONList(dec, "the report's runs", func() error {
			return walkJSONObject(dec, "a run", func(key string) (bool, error) {
				if key != "results" {
					return false, nil
				}
				return true, walkJSONList(dec, "a run's results", func() error {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						return err
					}
					return visit(raw)
				})
			})
		})
	})
}

// walkJSONObject reads an object, or null, member by member. member is given each member's name
// and reports whether it read the value. A value it did not read is skipped. A name member reads
// twice is an error.
func walkJSONObject(dec *json.Decoder, what string, member func(key string) (bool, error)) error {
	open, err := dec.Token()
	if err != nil || open == nil {
		return err
	}
	if open != json.Delim('{') {
		return errors.New(what + " is not an object")
	}
	read := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string) // a member's name is always a string
		if read[key] {
			return errors.New(what + " names " + key + " twice")
		}
		ok, err := member(key)
		if err != nil {
			return err
		}
		if ok {
			read[key] = true
			continue
		}
		var skipped json.RawMessage
		if err := dec.Decode(&skipped); err != nil {
			return err
		}
	}
	_, err = dec.Token() // the closing brace
	return err
}

// walkJSONList reads a list, or null, calling item to read each element.
func walkJSONList(dec *json.Decoder, what string, item func() error) error {
	open, err := dec.Token()
	if err != nil || open == nil {
		return err
	}
	if open != json.Delim('[') {
		return errors.New(what + " are not a list")
	}
	for dec.More() {
		if err := item(); err != nil {
			return err
		}
	}
	_, err = dec.Token() // the closing bracket
	return err
}

// decodeJSON decodes one JSON value, keeping each number as it was written.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
