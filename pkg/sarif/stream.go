package sarif

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// FromSARIFFile reads the SARIF log at path into a Report, as FromSARIF reads one held in memory,
// holding one result of the file at a time rather than the whole document.
//
// A report a tool writes over a long history runs to gigabytes, nearly all of it results. Decoding
// it whole holds the file and every result decoded beside it, at several times the file's size,
// when what the run keeps is the Report. The file is read twice: once for what each run says about
// itself, its rules above all, which a result inherits from and which SARIF lets a run write after
// its results, and once for the results.
//
// A document is read as FromSARIF reads it, with one difference: a member named twice in the log
// or a run is an error, where decoding whole keeps the last.
func FromSARIFFile(path string) (Report, error) {
	var (
		version string
		hasRuns bool
		runs    []sarifRun
	)
	// A file that cannot be read is that, rather than a file that is not SARIF.
	if _, err := os.Stat(path); err != nil {
		return Report{}, err
	}
	err := walkFile(path, func(dec *json.Decoder) error {
		return walkObject(dec, "the log", func(key string) (bool, error) {
			switch key {
			case "version":
				return true, dec.Decode(&version)
			case "runs":
				hasRuns = true
				return true, walkList(dec, "the log's runs", func() error {
					run, err := readRunApartFromResults(dec)
					runs = append(runs, run)
					return err
				})
			}
			return false, nil
		})
	})
	if err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	if version == "" && !hasRuns {
		// Not a log. Read whole only to say what it is instead, which FromSARIF works out: a file
		// with neither member holds no results to be large with.
		data, err := os.ReadFile(path) // #nosec G304 -- the caller's path
		if err != nil {
			return Report{}, err
		}
		return FromSARIF(data)
	}

	var out Report
	readers := make([]runReader, len(runs))
	for i, run := range runs {
		readers[i] = out.readRun(i, run)
	}
	err = walkFile(path, func(dec *json.Decoder) error {
		return walkObject(dec, "the log", func(key string) (bool, error) {
			if key != "runs" {
				return false, nil
			}
			i := 0
			return true, walkList(dec, "the log's runs", func() error {
				rr := readers[i]
				i++
				return walkObject(dec, "a run", func(key string) (bool, error) {
					if key != "results" {
						return false, nil
					}
					return true, walkList(dec, "a run's results", func() error {
						var sr sarifResult
						if err := dec.Decode(&sr); err != nil {
							return err
						}
						out.Results = append(out.Results, rr.result(sr))
						return nil
					})
				})
			})
		})
	})
	if err != nil {
		return Report{}, fmt.Errorf("%w: %w", ErrNotSARIF, err)
	}
	return out, nil
}

// readRunApartFromResults reads one run, or null, with every member but its results, which it
// steps over one at a time.
func readRunApartFromResults(dec *json.Decoder) (sarifRun, error) {
	members := map[string]json.RawMessage{}
	err := walkObject(dec, "a run", func(key string) (bool, error) {
		if key != "results" {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return true, err
			}
			members[key] = raw
			return true, nil
		}
		return true, walkList(dec, "a run's results", func() error {
			var skipped json.RawMessage
			return dec.Decode(&skipped)
		})
	})
	if err != nil {
		return sarifRun{}, err
	}
	var run sarifRun
	if len(members) == 0 {
		return run, nil
	}
	joined, err := json.Marshal(members)
	if err != nil {
		return sarifRun{}, err
	}
	return run, json.Unmarshal(joined, &run)
}

// walkFile opens path and hands a decoder over it to walk. Nothing after the first value is read.
func walkFile(path string, walk func(*json.Decoder) error) error {
	f, err := os.Open(path) // #nosec G304 -- the caller's path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return walk(json.NewDecoder(bufio.NewReader(f)))
}

// walkObject reads an object, or null, member by member. member is given each member's name and
// reports whether it read the value; a value it did not read is stepped over. A name read twice is
// an error.
func walkObject(dec *json.Decoder, what string, member func(key string) (bool, error)) error {
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

// walkList reads a list, or null, calling item to read each element.
func walkList(dec *json.Decoder, what string, item func() error) error {
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
