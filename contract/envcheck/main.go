// envcheck asserts that the simulator satisfies the contract the Terraform azuread provider
// relies on, by running the provider's own code against it.
//
// It uses hashicorp/go-azure-sdk at the version the provider pins, so an SDK change that breaks
// the simulator surfaces here rather than as a confusing provider error.
//
//	envcheck <endpoint>                                  # cloud metadata discovery only
//	envcheck <endpoint> <tenant> <client-id> <secret>    # also acquire a token
//
// Set SSL_CERT_FILE to the simulator's CA when it serves a generated certificate.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/go-azure-sdk/sdk/auth"
	"github.com/hashicorp/go-azure-sdk/sdk/environments"
)

func main() {
	if len(os.Args) != 2 && len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: envcheck <endpoint> [<tenant> <client-id> <secret>]")
		os.Exit(2)
	}

	env := checkDiscovery(os.Args[1])
	if len(os.Args) == 5 {
		checkToken(env, os.Args[2], os.Args[3], os.Args[4])
	}
	fmt.Println("OK")
}

// checkDiscovery runs the same call the provider makes when metadata_host is set.
func checkDiscovery(endpoint string) *environments.Environment {
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
	if env.Authorization == nil || env.Authorization.LoginEndpoint == "" {
		fail("the environment has no login endpoint")
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", env.Authorization.LoginEndpoint, "a-tenant")
	if strings.Contains(strings.TrimPrefix(tokenURL, "https://"), "//") {
		fail("the token URL %q contains a double slash; loginEndpoint must not end in a slash", tokenURL)
	}

	fmt.Printf("name:           %s\n", env.Name)
	fmt.Printf("graph endpoint: %s\n", *graphEndpoint)
	fmt.Printf("graph scope:    %s\n", *scope)
	fmt.Printf("login endpoint: %s\n", env.Authorization.LoginEndpoint)
	fmt.Printf("token url:      %s\n", tokenURL)
	return env
}

// checkToken acquires a token through the provider's own client-credentials authorizer, which
// also parses the token's claims to work out when to refresh it.
func checkToken(env *environments.Environment, tenant, clientID, secret string) {
	creds := auth.Credentials{
		Environment:                           *env,
		TenantID:                              tenant,
		ClientID:                              clientID,
		ClientSecret:                          secret,
		EnableAuthenticatingUsingClientSecret: true,
	}

	authorizer, err := auth.NewAuthorizerFromCredentials(context.Background(), creds, env.MicrosoftGraph)
	if err != nil {
		fail("building the authorizer: %v", err)
	}

	token, err := authorizer.Token(context.Background(), &http.Request{})
	if err != nil {
		fail("acquiring a token: %v", err)
	}
	if token.TokenType != "Bearer" {
		fail("expected a Bearer token, got %q", token.TokenType)
	}
	if token.AccessToken == "" {
		fail("the access token was empty")
	}
	// A zero expiry means the SDK could not read `iat` out of the token's claims.
	if token.Expiry.IsZero() {
		fail("the SDK could not determine the token expiry from its claims")
	}

	fmt.Printf("token type:     %s\n", token.TokenType)
	fmt.Printf("token expiry:   %s\n", token.Expiry.Format("2006-01-02T15:04:05Z07:00"))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
