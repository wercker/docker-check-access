package auth

import "errors"

//ErrUnexpectedResponse is the error thrown when we get a result from the registry that the library wasn't able to parse
var ErrUnexpectedResponse = errors.New("Unexpected Response")
