FROM openjdk:8-jre-alpine
WORKDIR @docker.app.directory@
VOLUME /tmp

# Install pre-requisites
RUN apk --no-cache add curl

# Copy files
COPY WEB-INF/lib ./lib
COPY WEB-INF/lib-provided ./lib-provided
COPY META-INF ./META-INF
COPY WEB-INF/classes .

# Create system user
RUN adduser -h @docker.app.directory@ -G users -u 1000 -D default
USER 1000

# Set runtime parameters
ENTRYPOINT ["java","-cp",".:./lib/*:./lib-provided/*","@start-class@"]
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 CMD curl -sSf http://localhost:8080/actuator/health || exit 1
EXPOSE 8080
