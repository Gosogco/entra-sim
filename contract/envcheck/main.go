// envcheck asserts that the simulator's cloud metadata document satisfies the contract the
// Terraform azuread provider relies on, by running the provider's own discovery code against it.
//
// It uses hashicorp/go-azure-sdk at the version the provider pins, so a change in the SDK that
// breaks the simulator surfaces here rather than as a confusing provider error.
//
// Usage: envcheck https://host:port
// Set SSL_CERT_FILE to the simulator's CA when it serves a generated certificate.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-azure-sdk/sdk/environments"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: envcheck https://host:port")
		os.Exit(2)
	}
	endpoint := os.Args[1]

	env, err := environments.FromEndpoint(context.Background(), endpoint)
	if err != nil {
		fail("discovering the environment: %v", err)
	}

	if env.Name == "" {
		fail("the environment has no name")
	}
	if env.MicrosoftGraph == nil {
		fail("Microsoft Graph was not configured for this environment")
	}

	graphEndpoint, ok := env.MicrosoftGraph.Endpoint()
	if !ok || *graphEndpoint == "" {
		fail("the Microsoft Graph endpoint could not be determined")
	}
	scope, err := environments.Scope(env.MicrosoftGraph)
	if err != nil {
		fail("deriving the Graph scope: %v", err)
	}

	// The SDK builds the token URL by concatenation, so a trailing slash on the login endpoint
	// puts a double slash into every token request the provider makes.
	loginEndpoint := env.Authorization.LoginEndpoint
	if loginEndpoint == "" {
		fail("the environment has no login endpoint")
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", loginEndpoint, "a-tenant")
	if strings.Contains(strings.TrimPrefix(tokenURL, "https://"), "//") {
		fail("the token URL %q contains a double slash; loginEndpoint must not end in a slash", tokenURL)
	}

	fmt.Printf("name:           %s\n", env.Name)
	fmt.Printf("graph endpoint: %s\n", *graphEndpoint)
	fmt.Printf("graph scope:    %s\n", *scope)
	fmt.Printf("login endpoint: %s\n", loginEndpoint)
	fmt.Printf("token url:      %s\n", tokenURL)
	fmt.Println("OK")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
