FROM openjdk:8-jre-alpine
WORKDIR @docker.app.directory@
VOLUME /tmp

COPY WEB-INF/lib ./lib
COPY WEB-INF/lib-provided ./lib-provided
COPY META-INF ./META-INF
COPY WEB-INF/classes .

RUN adduser -h @docker.app.directory@ -G users -u 1000 -D default
USER 1000

ENTRYPOINT ["java","-cp",".:./lib/*:./lib-provided/*","@start-class@"]
EXPOSE 8080
