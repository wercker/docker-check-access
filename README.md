# Docker-Check-Access

Sometimes you find yourself between a rock and hard place. In this case, you're in charge of a multi-tenant docker environment but you're not in directly in charge of authorization of all the containers in your system. What do you do?

Well, this package is designed to help with that. We'll make calls to a docker registry provider on your behalf to find out if a user has permission to touch a container in your docker environment.

Example use:

```go
package modify

import (
    "github.com/fsouza/go-dockerclient"
	"github.com/wercker/docker-check-access"
)

func ModifyLocalContainer(auth auth.Authenticator, container *docker.Container) error {
    //check to see if we have an error, or we can't access
    if ok, err := auth.CheckAccess(); err != nil || !ok {
        return errors.New("You can't access that!")
    }
   // move along with messing with your local container
}
```
