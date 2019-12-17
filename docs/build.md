# Build

## Locally

To build the application and Docker image locally, execute the following command, from the project directory:

    ./mvnw -DskipTests -Dfrontend-build -Ddocker-build -Ddocker.image.tag=latest clean package dockerfile:build

A Docker image tagged `fcrespel/karaplan:latest` will then be created.

You may set the `docker.image.prefix` system property to specify a different Docker registry/repository.

## Using GitLab

A `.gitlab-ci.yml` file is available at the root of the repository to automate the build/test/publish pipeline on [GitLab](https://gitlab.com).

The pipeline will produce a WAR file and a Docker image, and push it to a Docker registry.

Required environment variables:

* `DOCKER_USERNAME`: Docker registry username
* `DOCKER_PASSWORD`: Docker registry password

Optional environment variables:

* `MVN_ENV_OPTS`: Maven environment options (known as MAVEN_OPTS)
* `MVN_BUILD_OPTS`: Maven build options (arguments, profiles, system properties)
* `MVN_GOALS`: Maven build goals
* `DOCKER_REPO`: Docker image registry/repository
* `DOCKER_IMAGE`: Docker image name

## Using Jenkins

A `Jenkinsfile` file is available at the root of the repository to automate the build/test/publish pipeline on [Jenkins](https://jenkins.io).

The pipeline will produce a WAR file and a Docker image, and push it to a Docker registry.

Optional parameters:

* `mvn_env_opts`: Maven environment options (known as MAVEN_OPTS)
* `mvn_build_opts`: Maven build options (arguments, profiles, system properties)
* `mvn_goals`: Maven build goals

## Using Google Cloud Build

See the Google Cloud Platform [deployment](deployment/gcp/build) documentation.
