package auth

import "errors"

//ErrUnexpectedResponse is the error thrown when we get a result from the registry that the library wasn't able to parse
var ErrUnexpectedResponse = errors.New("Unexpected Response")

//ErrRepoNotFound is the error thrown when we were unable to find the repository you want to check the user's access to on the remote repository
var ErrRepoNotFound = errors.New("Unable to find repository on remote registry")

//ErrRepoNotAuthorized is the error thrown when user could not be authroized on the repository present on remote regustry with supplied credentials
var ErrRepoNotAuthorized = errors.New("Not Authorized to access the repository")
