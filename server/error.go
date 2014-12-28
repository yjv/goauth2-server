package server

import (
	"fmt"
)

type ErrorCode int

const (
	StorageSearchFailed  ErrorCode = iota
	InvalidScope         ErrorCode = iota
	RequiredValueMissing ErrorCode = iota
	GrantNotFound        ErrorCode = iota
	Unexpected           ErrorCode = iota
)

type OauthError interface {
	error
	OauthErrorCode() ErrorCode
}

type OauthErrorWithPrevious interface {
	OauthError
	Previous() error
}

type StorageSearchFailedError struct {
	storedType string
	previous   error
}

func (error *StorageSearchFailedError) Error() string {
	return fmt.Sprintf("Failed to find %s.", error.storedType)
}

func (error *StorageSearchFailedError) OauthErrorCode() ErrorCode {
	return StorageSearchFailed
}

func (error *StorageSearchFailedError) Previous() error {
	return error.previous
}

type RequiredValueMissingError struct {
	value string
}

func (error *RequiredValueMissingError) Error() string {
	return fmt.Sprintf("%s is required.", error.value)
}

func (error *RequiredValueMissingError) OauthErrorCode() ErrorCode {
	return RequiredValueMissing
}

type GrantNotFoundError struct {
	name string
}

func (error *GrantNotFoundError) Error() string {
	return fmt.Sprintf("The grant named %s was not found.", error.name)
}

func (error *GrantNotFoundError) OauthErrorCode() ErrorCode {
	return GrantNotFound
}

type UnexpectedError struct {
	error error
}

func (error *UnexpectedError) Error() string {
	return "An unexpected error occured."
}

func (error *UnexpectedError) OauthErrorCode() ErrorCode {
	return Unexpected
}

type InvalidScopeError struct {
	name string
	previous error
}

func (error *InvalidScopeError) Error() string {
	return fmt.Sprintf("the scope named %s is invalid.", error.name)
}

func (error *InvalidScopeError) OauthErrorCode() ErrorCode {
	return InvalidScope
}

func (error *InvalidScopeError) Previous() error {
	return error.previous
}
