// Package templates holds the a-h/templ source files for every server-rendered
// page. The .templ files in this directory are compiled by `templ generate`
// into sibling *_templ.go files. Both source and generated files are committed.
//
// To regenerate after editing a .templ file:
//
//	templ generate -path internal/web/templates
//
// CI runs `templ generate` and fails on dirty diffs.
package templates

//go:generate templ generate -path .
