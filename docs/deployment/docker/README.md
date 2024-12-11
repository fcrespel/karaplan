# Docker and Docker Compose

## Docker

To run the application as a Docker container, execute the following command:

    docker run -d --name karaplan -p 8080:8080 ghcr.io/fcrespel/karaplan:latest

The application will then be available at [http://localhost:8080](http://localhost:8080)

All configuration values may be overridden with environment variables (as supported by Spring Boot), such as the following:

- SPRING_DATASOURCE_USERNAME
- SPRING_DATASOURCE_PASSWORD
- SPRING_DATASOURCE_URL
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID
- SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET

## Docker Compose

To run the application using [Docker Compose](https://docs.docker.com/compose/), you may use and adapt the following example:

```
version: '3.5'
services:
  mysql:
    image: mysql:8.0
    restart: always
    volumes:
      - './mysql:/var/lib/mysql'
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: 'yes'
      MYSQL_DATABASE: 'karaplan'
      MYSQL_USER: 'karaplan'
      MYSQL_PASSWORD: 'toComplete'
  karaplan:
    image: ghcr.io/fcrespel/karaplan:master
    restart: always
    environment:
      JAVA_TOOL_OPTIONS: '-Xms512m -Xmx1024m'
      SPRING_DATASOURCE_USERNAME: 'karaplan'
      SPRING_DATASOURCE_PASSWORD: 'toComplete'
      SPRING_DATASOURCE_URL: 'jdbc:mysql://mysql:3306/karaplan'
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTID: 'toComplete'
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENTSECRET: 'toComplete'
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTID: 'toComplete'
      SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENTSECRET: 'toComplete'
```