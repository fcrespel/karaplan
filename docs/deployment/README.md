# Deployment

This directory contains specific deployment instructions and examples for:

* [Docker](docker) and Docker Compose
* [Google Cloud Platform (GCP)](gcp)

## Database

An external database is required for deployment, e.g. MySQL. Other database types supported by Spring Boot, such as PostgreSQL, may also work but have not been tested.

## Authentication

Several identity providers are supported for authentication using OAuth 2.0, and need to be configured. For real-world hosting (not localhost), you will first need to register a custom domain name (_your.domain_ in the examples below) and use HTTPS.

- Google:
  - if you don't have a Google account, [create it](https://support.google.com/accounts/answer/27441)
  - then [create a Google OAuth client](https://developers.google.com/identity/protocols/OAuth2WebServer#creatingcred)
  - add _Authorized redirect URIs_: https://your.domain/login/oauth2/code/google
  - copy the OAuth client credentials (clientID / clientSecret)
- Facebook:
  - if you don't have a Facebook account, [create it](https://www.facebook.com/r.php)
  - then [create a new app](https://developers.facebook.com/apps)
  - in the _Products_ section, enable _Facebook Login_
  - add _Valid OAuth redirect URIs_: https://your.domain/login/oauth2/code/facebook
  - copy the OAuth client credentials (clientID / clientSecret) from the _Settings > General_ section
- GitHub:
  - if you don't have a GitHub account, [create it](https://github.com/join)
  - then [register a new OAuth application](https://github.com/settings/applications/new)
  - set _Authorization callback URL_: https://your.domain/login/oauth2/code/github
  - copy the OAuth client credentials (clientID / clientSecret)

See specific deployment instructions to learn how to configure the clientID/clientSecret.
