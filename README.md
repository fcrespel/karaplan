[![Pipeline Status](https://gitlab.com/fcrespel/karaplan/badges/master/pipeline.svg)](https://gitlab.com/fcrespel/karaplan/pipelines)
[![Docker Pulls](https://img.shields.io/docker/pulls/fcrespel/karaplan.svg)](https://hub.docker.com/r/fcrespel/karaplan)
[![License](https://img.shields.io/github/license/fcrespel/karaplan.svg)](https://opensource.org/licenses/MIT)

# KaraPlan

**KaraPlan** is a Karaoke Planner web application with song search, ratings, comments, playlists and more.

## Developing

To develop this project you need [Java 8](https://adoptopenjdk.net) and [NodeJS](https://nodejs.org). Maven is included in the project with `mvnw`.

You may use your preferred IDE to develop this project, e.g. [VS Code](https://code.visualstudio.com). Please respect the existing coding style.

### Backend 

Local backend development uses an embedded H2 database and Tomcat server listening on port 8080. Appropriate credentials must be supplied in a `application-local.yml` file in the `src/main/resources` directory.

You may launch the backend as a Spring Boot app with the following arguments:

    -Dspring.profiles.active=local

An appropriate launch configuration is already included for VS Code.

The backend will then be available at [http://localhost:8080](http://localhost:8080)

### Frontend

Local frontend development uses a NodeJS server listening on port 4200 with live reload support.

First install dependencies with NPM, from the `src/main/nodejs` directory:

    npm install

You may launch the frontend as a NodeJS server with the following command, from the `src/main/nodejs` directory:

    ng serve

An appropriate launch configuration is already included for VS Code.

The frontend will then be available at [http://localhost:4200](http://localhost:4200)

## Building

To build the application and Docker image locally, execute the following command, from the project directory:

    ./mvnw -DskipTests -Dfrontend-build -Ddocker-build -Ddocker.image.tag=latest clean package dockerfile:build

A Docker image tagged `fcrespel/karaplan:latest` will then be created.

## Running

To run the application as a Docker container, execute the following command:

    docker run -d --name karaplan -p 8080:8080 fcrespel/karaplan:latest

The application will then be available at [http://localhost:8080](http://localhost:8080)

All configuration values may be overridden with environment variables (as supported by Spring Boot), such as the following:

- SPRING_DATASOURCE_USERNAME
- SPRING_DATASOURCE_PASSWORD
- SPRING_DATASOURCE_URL
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET

## Legal notice

**KaraPlan** is licensed under the open-source [MIT License](https://opensource.org/licenses/MIT).

**KaraPlan** is provided "as is" with no warranty of any kind, express or implied. Please refer to the license terms for more information.

**KaraPlan** makes use of the [Recisio](https://www.recisio.com) song catalog, the [KaraFun](https://www.karafun.com), [KaraFun Bar](https://www.karafunbar.com) and [Karaoke Version](https://www.karaoke-version.com) APIs on a fair use basis. It is not affiliated in any way with Recisio or its subsidiaries. All trademarks are the property of their respective owner.
