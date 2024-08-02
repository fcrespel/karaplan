FROM eclipse-temurin:17-jre
WORKDIR @docker.app.directory@

# Copy files
COPY WEB-INF/lib ./lib
COPY WEB-INF/lib-provided ./lib-provided
COPY META-INF ./META-INF
COPY WEB-INF/classes .

# Set runtime parameters
USER 1000
ENV JAVA_TOOL_OPTIONS="-Xverify:none -XX:+TieredCompilation -XX:TieredStopAtLevel=1"
ENTRYPOINT ["java","-cp",".:./lib/*:./lib-provided/*","@start-class@"]
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 CMD curl -sSf http://localhost:8080/actuator/health/liveness || exit 1
EXPOSE 8080
