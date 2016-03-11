package auth

//Scope defines the possible types of scopes
type Scope string

const (
	Push Scope = "PUSH"
	Pull Scope = "PULL"
)

// An Authenticator is the interface that wraps the CheckAccess method
// It implements one method called CheckAccess which checks to see if a user is allowed to read and write to a certain docker repository.
// It returns a boolean value indicating the user's permissions, and an error if any request failed when trying check access
type Authenticator interface {
	CheckAccess(string, Scope) (bool, error)
}
