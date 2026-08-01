package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	opts := options{}
	flag.StringVar(&opts.command, "command", "", "shell command to show above the output")
	flag.StringVar(&opts.stopAt, "stop-at", "", "truncate at the first line with this prefix")
	flag.IntVar(&opts.exitCode, "exit", -1, "exit code to show below the output (negative omits it)")
	flag.Parse()

	if err := run(os.Stdin, os.Stdout, opts); err != nil {
		fmt.Fprintln(os.Stderr, "ansi2html:", err)
		os.Exit(1)
	}
}

func run(r io.Reader, w io.Writer, opts options) error {
	in, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	out, err := convert(string(in), opts)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, out)
	return err
}
