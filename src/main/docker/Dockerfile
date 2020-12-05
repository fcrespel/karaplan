FROM adoptopenjdk:11-jre-hotspot
WORKDIR @docker.app.directory@
VOLUME /tmp

# Copy files
COPY WEB-INF/lib ./lib
COPY WEB-INF/lib-provided ./lib-provided
COPY META-INF ./META-INF
COPY WEB-INF/classes .

# Create system user
RUN useradd -d @docker.app.directory@ -G users -u 1000 default
USER 1000

# Set runtime parameters
ENV JAVA_TOOL_OPTIONS="-Xverify:none -XX:+TieredCompilation -XX:TieredStopAtLevel=1"
ENTRYPOINT ["java","-cp",".:./lib/*:./lib-provided/*","@start-class@"]
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 CMD curl -sSf http://localhost:8080/actuator/health/liveness || exit 1
EXPOSE 8080
