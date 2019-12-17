# Development

To develop this project you need [Java 8](https://adoptopenjdk.net) and [NodeJS](https://nodejs.org). Maven is included in the project with `mvnw`.

You may use your preferred IDE to develop this project, e.g. [VS Code](https://code.visualstudio.com). Please respect the existing coding style.

## Backend 

Local backend development uses an embedded H2 database and Tomcat server listening on port 8080.

Several identity providers are supported for authentication using OAuth 2.0, and need to be configured:
- Google:
  - if you don't have a Google account, [create it](https://support.google.com/accounts/answer/27441)
  - then [create a Google OAuth client](https://developers.google.com/identity/protocols/OAuth2WebServer#creatingcred)
  - add _Authorized redirect URIs_: http://localhost:4200/login/oauth2/code/google
  - copy the OAuth client credentials (clientID / clientSecret)
- Facebook:
  - if you don't have a Facebook account, [create it](https://www.facebook.com/r.php)
  - then [create a new app](https://developers.facebook.com/apps)
  - in the _Products_ section, enable _Facebook Login_
  - add _Valid OAuth redirect URIs_: http://localhost:4200/login/oauth2/code/facebook
  - copy the OAuth client credentials (clientID / clientSecret) from the _Settings > General_ section
- GitHub:
  - if you don't have a GitHub account, [create it](https://github.com/join)
  - then [register a new OAuth application](https://github.com/settings/applications/new)
  - set _Authorization callback URL_: http://localhost:4200/login/oauth2/code/github
  - copy the OAuth client credentials (clientID / clientSecret)

Your OAuth client credentials must be supplied in a `application-local.yml` file in the `src/main/resources` directory.
See [this Spring Security sample](https://github.com/spring-projects/spring-security/tree/5.1.x/samples/boot/oauth2login) for more information about configuring the OAuth 2.0 provider details.

You may launch the backend as a Spring Boot app with the following arguments:

    -Dspring.profiles.active=local

An appropriate launch configuration is already included for VS Code.

The backend will then be available at [http://localhost:8080](http://localhost:8080)

## Frontend

Local frontend development uses a NodeJS server listening on port 4200 with live reload support.

First install dependencies with NPM, from the `src/main/nodejs` directory:

    npm install

You may launch the frontend as a NodeJS server with the following command, from the `src/main/nodejs` directory:

    ng serve

An appropriate launch configuration is already included for VS Code.

The frontend will then be available at [http://localhost:4200](http://localhost:4200)
