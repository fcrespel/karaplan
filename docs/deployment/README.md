# Deployment

This directory contains specific deployment instructions and examples for:

* [Docker](docker/README.md) and Docker Compose
* [Helm](helm/README.md) chart for Kubernetes
* [Google Cloud Platform (GCP)](gcp/README.md)
* [Terraform](terraform/README.md) infrastructure as code

## Database

An external database is required for deployment, e.g. MySQL. Other database types supported by Spring Boot, such as PostgreSQL, may also work but have not been tested.

## Authentication

Several identity providers are supported for authentication using OAuth 2.0, and need to be configured. For real-world hosting (not localhost), you will first need to register a custom domain name (_your.domain_ in the examples below) and use HTTPS.

See specific deployment instructions to learn how to configure the clientID / clientSecret.

### Google

* If you don't have a Google account, [create it](https://support.google.com/accounts/answer/27441)
* Then [create a Google OAuth client](https://developers.google.com/identity/protocols/OAuth2WebServer#creatingcred)
* Add _Authorized redirect URIs_: `https://your.domain/login/oauth2/code/google`
* Copy the OAuth client credentials (clientID / clientSecret)

### GitHub

* If you don't have a GitHub account, [create it](https://github.com/join)
* Then [register a new OAuth application](https://github.com/settings/applications/new)
* Set _Authorization callback URL_: `https://your.domain/login/oauth2/code/github`
* Copy the OAuth client credentials (clientID / clientSecret)
