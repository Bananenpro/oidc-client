package oidc

import "errors"

var (
	ErrInvalidScope = errors.New("invalid_scope")
	ErrAccessDenied = errors.New("access_denied")
	ErrInvalidState = errors.New("invalid_state")
	ErrInvalidToken = errors.New("invalid_token")
	ErrExpiredToken = errors.New("expired_token")
)
