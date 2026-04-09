# Development

To develop this project you need [Java](https://adoptium.net) 21 or higher and [NodeJS](https://nodejs.org) 22 or higher. Maven is included in the project with `mvnw`.

You may use your preferred IDE to develop this project, e.g. [VS Code](https://code.visualstudio.com). Please respect the existing coding style.

## Backend 

Local backend development uses an embedded H2 database and Tomcat server listening on port 8080.

### Authentication

Several identity providers are supported for authentication using OAuth 2.0, and need to be configured:

* Google:
    * If you don't have a Google account, [create it](https://support.google.com/accounts/answer/27441)
    * Then [create a Google OAuth client](https://developers.google.com/identity/protocols/OAuth2WebServer#creatingcred)
    * Add _Authorized redirect URIs_: `http://localhost:4200/login/oauth2/code/google`
    * Copy the OAuth client credentials (clientID / clientSecret)

* GitHub:
    * If you don't have a GitHub account, [create it](https://github.com/join)
    * Then [register a new OAuth application](https://github.com/settings/applications/new)
    * Set _Authorization callback URL_: `http://localhost:4200/login/oauth2/code/github`
    * Copy the OAuth client credentials (clientID / clientSecret)

Your OAuth client credentials must be supplied in a `application-local.yml` file in the `src/main/resources` directory, such as the following:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: your-google-client-id
            client-secret: your-google-client-secret
          github:
            client-id: your-github-client-id
            client-secret: your-github-client-secret
```

### Database

Optionally, you may use [Docker Compose](https://docs.docker.com/compose/) to launch a MariaDB database for local development. Set the following property in `application-local.yml` to let Spring Boot start it and configure it as the datasource:

```yaml
spring:
  docker:
    compose:
      enabled: true
```

### Observability

Optionally, you may use [Docker Compose](https://docs.docker.com/compose/) to launch a Grafana/Prometheus/Loki/Tempo stack for observability. Run the following command from the project root to launch it:

```sh
docker compose up -d grafana
```

The Grafana interface will then be available at [http://localhost:3000](http://localhost:3000)

Add the following properties to `application-local.yml` to configure OpenTelemetry to export metrics, logs and traces to it:

```yaml
otel:
  sdk:
    disabled: false
  instrumentation:
    common:
      enduser:
        id:
          enabled: true
  resource:
    attributes:
      deployment.environment: dev
```

### Launching

You may launch the backend as a Spring Boot app with the following command from the project root:

```
./mvnw spring-boot:run -Dspring-boot.run.profiles=local
```

An appropriate launch configuration is already included for VS Code.

The backend will then be available at [http://localhost:8080](http://localhost:8080)

## Frontend

Local frontend development uses a NodeJS server listening on port 4200 with live reload support.

### Dependencies

First install dependencies with NPM, from the `src/main/nodejs` directory:

```sh
npm install
```

### Launching

You may launch the frontend as a NodeJS server with the following command, from the `src/main/nodejs` directory:

```sh
npm run start
```

An appropriate launch configuration is already included for VS Code.

The frontend will then be available at [http://localhost:4200](http://localhost:4200)
