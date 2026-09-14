// Parse stdin only. Never import the interpreter or execute shell input.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"mvdan.cc/sh/v3/syntax"
	"mvdan.cc/sh/v3/syntax/typedjson"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "bash" && os.Args[1] != "zsh" && os.Args[1] != "posix") {
		os.Exit(2)
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 32769))
	if err != nil || len(input) > 32768 {
		os.Exit(2)
	}
	dialect := syntax.LangBash
	if len(os.Args) > 1 && os.Args[1] == "posix" {
		dialect = syntax.LangPOSIX
	}
	if os.Args[1] == "zsh" {
		dialect = syntax.LangZsh
	}
	node, err := syntax.NewParser(syntax.Variant(dialect)).Parse(bytes.NewReader(input), "request")
	if err != nil {
		// Do not copy potentially sensitive command text into stderr.
		fmt.Fprintln(os.Stderr, "Invalid or unsupported shell syntax")
		os.Exit(1)
	}
	if err := typedjson.Encode(os.Stdout, node); err != nil {
		os.Exit(2)
	}
}
