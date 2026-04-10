# KaraPlan AI Agents Instructions

**KaraPlan** is a Karaoke Planner web application with song search, ratings, comments, playlists and more.

Backend: **Java 21 / Spring Boot 4**, frontend: **Angular 21** (served by Spring Boot). See [README.md](../README.md) and [docs/](../docs/) for full context.

## Build & Test

```sh
# Full build (backend + frontend + Docker image)
./mvnw -Dfrontend-build -Ddocker-build -Ddocker.image.tag=latest clean package dockerfile:build

# Backend unit tests only
./mvnw test

# Backend unit + integration tests
./mvnw verify

# Run backend locally (profile: local, port 8080)
./mvnw spring-boot:run -Dspring-boot.run.profiles=local

# Frontend dev server (port 4200, proxies /api to backend)
cd src/main/nodejs && npm start

# Frontend tests
cd src/main/nodejs && npm test
```

See [docs/build.md](../docs/build.md) and [docs/development.md](../docs/development.md) for detailed instructions.

## Architecture

```
src/main/java/me/crespel/karaplan/
├── config/          Spring configuration & beans
├── security/        OAuth2 providers, authentication wrappers
├── domain/          JPA entities (User, Playlist, PlaylistSong, Song, Artist, Style, etc.)
├── model/           DTOs and API models
├── repository/      Spring Data JPA repositories
├── service/         Business logic (interfaces at root, implementations in subdirectories)
└── web/             Spring MVC controllers
    └── api/         REST API
src/main/nodejs/     Angular frontend
├── src/app/         Application root (app.component, app.config, app.routes)
│   ├── about/       About page
│   ├── alert/       Alert toast component
│   ├── footer/      Footer
│   ├── home/        Home page
│   ├── login/       Login page
│   ├── models/      TypeScript interfaces/models (DTOs)
│   ├── navbar/      Navigation bar
│   ├── playlists/   Playlists section
│   ├── services/    Services (API calls, state)
│   ├── shared/      Reusable components & pipes
│   ├── songs/       Songs section
│   └── user/        User profile section
└── src/assets/      Static assets
│   └── i18n/        Internationalization files
src/main/resources/  Static resources and configuration
└── db/migration/    Flyway scripts (vendor dirs: mariadb/, mysql/, postgresql/)
```

## Key Conventions

- **Database migrations**: Flyway, vendor-specific scripts in `src/main/resources/db/migration/{mariadb,mysql,postgresql}/`. Always add a new versioned script; never modify existing ones.
- **JPA**: Globally quoted identifiers (`hibernate.globally_quoted_identifiers=true`), legacy naming strategy. Use `AuthenticationAuditorAware` for `createdBy`/`modifiedBy`.
- **Jackson 3**: Packages are `tools.jackson.*` (not `com.fasterxml.jackson.*`). XML annotations: `tools.jackson.dataformat.xml.annotation.*`. Hibernate integration: `tools.jackson.datatype:jackson-datatype-hibernate7`.
- **Spring Security**: Use `PathPatternRequestMatcher.pathPattern(...)` (Spring Security 7 API).
- **RestClient test slice**: Use `org.springframework.boot.restclient.test.autoconfigure.RestClientTest`.
- **Integration tests**: Suffixed with `IT`, run by Failsafe (`mvnw verify`), not by `mvnw test`.
- **Angular**: Use signals, standalone components and template-driven forms.
- **Internationalization**: Use `ngx-translate` for i18n with translation files in `src/main/nodejs/src/assets/i18n/`. Always externalize user-facing strings to translation files; never hardcode them in templates or components.
