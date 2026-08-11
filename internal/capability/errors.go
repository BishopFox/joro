package capability

import "fmt"

// Machine-readable codes carried by Error. The MCP layer maps these to protocol
// errors, the UI groups Activity rows by them, and the guard matrix test asserts
// them, so they are a contract rather than log text.
const (
	CodeForbidden       = "forbidden"
	CodeScopeDisabled   = "scope_disabled"
	CodeScopeEmpty      = "scope_empty"
	CodeOutOfScope      = "out_of_scope"
	CodeHostNotAllowed  = "host_not_allowed"
	CodeTokenRestricted = "token_restricted"
	CodeRateLimited     = "rate_limited"
	CodeBusy            = "busy"
	CodeInvalidArgs     = "invalid_args"
	CodeOutputTooLarge  = "output_too_large"
	CodeTimeout         = "timeout"
	CodeHandlerError    = "handler_error"
	CodePanic           = "panic"
)

// Error is a guard or handler failure with a machine-readable code.
//
// Msg is shown to the automation client, so it should name the fix: an agent that
// is told "scope is disabled; enable scope and add an include rule, or create the
// token with requireScope disabled" recovers, while one told "forbidden" retries
// the identical call.
type Error struct {
	Code         string
	Msg          string
	RetryAfterMs int
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Code
	}
	return e.Code + ": " + e.Msg
}

func errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// CodeOf returns the machine code for an error, defaulting to handler_error for
// anything a capability body returned that isn't already an *Error.
func CodeOf(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return CodeHandlerError
}
