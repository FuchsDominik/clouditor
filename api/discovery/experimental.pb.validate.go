// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: api/discovery/experimental.proto

package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on GraphEdge with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *GraphEdge) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on GraphEdge with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in GraphEdgeMultiError, or nil
// if none found.
func (m *GraphEdge) ValidateAll() error {
	return m.validate(true)
}

func (m *GraphEdge) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Id

	// no validation rules for Source

	// no validation rules for Target

	if len(errors) > 0 {
		return GraphEdgeMultiError(errors)
	}

	return nil
}

// GraphEdgeMultiError is an error wrapping multiple validation errors returned
// by GraphEdge.ValidateAll() if the designated constraints aren't met.
type GraphEdgeMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m GraphEdgeMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m GraphEdgeMultiError) AllErrors() []error { return m }

// GraphEdgeValidationError is the validation error returned by
// GraphEdge.Validate if the designated constraints aren't met.
type GraphEdgeValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GraphEdgeValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GraphEdgeValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GraphEdgeValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GraphEdgeValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GraphEdgeValidationError) ErrorName() string { return "GraphEdgeValidationError" }

// Error satisfies the builtin error interface
func (e GraphEdgeValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGraphEdge.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GraphEdgeValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GraphEdgeValidationError{}

// Validate checks the field values on UpdateResourceRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *UpdateResourceRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on UpdateResourceRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// UpdateResourceRequestMultiError, or nil if none found.
func (m *UpdateResourceRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *UpdateResourceRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetResource()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, UpdateResourceRequestValidationError{
					field:  "Resource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, UpdateResourceRequestValidationError{
					field:  "Resource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetResource()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpdateResourceRequestValidationError{
				field:  "Resource",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return UpdateResourceRequestMultiError(errors)
	}

	return nil
}

// UpdateResourceRequestMultiError is an error wrapping multiple validation
// errors returned by UpdateResourceRequest.ValidateAll() if the designated
// constraints aren't met.
type UpdateResourceRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m UpdateResourceRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m UpdateResourceRequestMultiError) AllErrors() []error { return m }

// UpdateResourceRequestValidationError is the validation error returned by
// UpdateResourceRequest.Validate if the designated constraints aren't met.
type UpdateResourceRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpdateResourceRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpdateResourceRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpdateResourceRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpdateResourceRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpdateResourceRequestValidationError) ErrorName() string {
	return "UpdateResourceRequestValidationError"
}

// Error satisfies the builtin error interface
func (e UpdateResourceRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpdateResourceRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpdateResourceRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpdateResourceRequestValidationError{}

// Validate checks the field values on UpdateResourceResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *UpdateResourceResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on UpdateResourceResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// UpdateResourceResponseMultiError, or nil if none found.
func (m *UpdateResourceResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *UpdateResourceResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetResource()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, UpdateResourceResponseValidationError{
					field:  "Resource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, UpdateResourceResponseValidationError{
					field:  "Resource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetResource()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return UpdateResourceResponseValidationError{
				field:  "Resource",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return UpdateResourceResponseMultiError(errors)
	}

	return nil
}

// UpdateResourceResponseMultiError is an error wrapping multiple validation
// errors returned by UpdateResourceResponse.ValidateAll() if the designated
// constraints aren't met.
type UpdateResourceResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m UpdateResourceResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m UpdateResourceResponseMultiError) AllErrors() []error { return m }

// UpdateResourceResponseValidationError is the validation error returned by
// UpdateResourceResponse.Validate if the designated constraints aren't met.
type UpdateResourceResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UpdateResourceResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UpdateResourceResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UpdateResourceResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UpdateResourceResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UpdateResourceResponseValidationError) ErrorName() string {
	return "UpdateResourceResponseValidationError"
}

// Error satisfies the builtin error interface
func (e UpdateResourceResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUpdateResourceResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UpdateResourceResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UpdateResourceResponseValidationError{}

// Validate checks the field values on ListGraphEdgesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *ListGraphEdgesRequest) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ListGraphEdgesRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ListGraphEdgesRequestMultiError, or nil if none found.
func (m *ListGraphEdgesRequest) ValidateAll() error {
	return m.validate(true)
}

func (m *ListGraphEdgesRequest) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for PageSize

	// no validation rules for PageToken

	// no validation rules for OrderBy

	// no validation rules for Asc

	if len(errors) > 0 {
		return ListGraphEdgesRequestMultiError(errors)
	}

	return nil
}

// ListGraphEdgesRequestMultiError is an error wrapping multiple validation
// errors returned by ListGraphEdgesRequest.ValidateAll() if the designated
// constraints aren't met.
type ListGraphEdgesRequestMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListGraphEdgesRequestMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListGraphEdgesRequestMultiError) AllErrors() []error { return m }

// ListGraphEdgesRequestValidationError is the validation error returned by
// ListGraphEdgesRequest.Validate if the designated constraints aren't met.
type ListGraphEdgesRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListGraphEdgesRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListGraphEdgesRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListGraphEdgesRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListGraphEdgesRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListGraphEdgesRequestValidationError) ErrorName() string {
	return "ListGraphEdgesRequestValidationError"
}

// Error satisfies the builtin error interface
func (e ListGraphEdgesRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListGraphEdgesRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListGraphEdgesRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListGraphEdgesRequestValidationError{}

// Validate checks the field values on ListGraphEdgesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *ListGraphEdgesResponse) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ListGraphEdgesResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ListGraphEdgesResponseMultiError, or nil if none found.
func (m *ListGraphEdgesResponse) ValidateAll() error {
	return m.validate(true)
}

func (m *ListGraphEdgesResponse) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetEdges() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ListGraphEdgesResponseValidationError{
						field:  fmt.Sprintf("Edges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ListGraphEdgesResponseValidationError{
						field:  fmt.Sprintf("Edges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ListGraphEdgesResponseValidationError{
					field:  fmt.Sprintf("Edges[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for NextPageToken

	if len(errors) > 0 {
		return ListGraphEdgesResponseMultiError(errors)
	}

	return nil
}

// ListGraphEdgesResponseMultiError is an error wrapping multiple validation
// errors returned by ListGraphEdgesResponse.ValidateAll() if the designated
// constraints aren't met.
type ListGraphEdgesResponseMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListGraphEdgesResponseMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListGraphEdgesResponseMultiError) AllErrors() []error { return m }

// ListGraphEdgesResponseValidationError is the validation error returned by
// ListGraphEdgesResponse.Validate if the designated constraints aren't met.
type ListGraphEdgesResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListGraphEdgesResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListGraphEdgesResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListGraphEdgesResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListGraphEdgesResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListGraphEdgesResponseValidationError) ErrorName() string {
	return "ListGraphEdgesResponseValidationError"
}

// Error satisfies the builtin error interface
func (e ListGraphEdgesResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListGraphEdgesResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListGraphEdgesResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListGraphEdgesResponseValidationError{}