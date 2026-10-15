# Directory Console: the server on a distroless Java 21 runtime, as the nonroot user (65532), with a
# read-only root file system. /data is the only writable path.
# Build with container/build.sh, which gathers the artifacts.

# distroless has no shell: this stage only makes /data owned by the nonroot user
FROM eclipse-temurin:21-jre AS prep
RUN mkdir -p /out/data && chown 65532:65532 /out/data && chmod 700 /out/data

FROM gcr.io/distroless/java21-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/PointBlueTechnology/directory-console" \
      org.opencontainers.image.title="Directory Console" \
      org.opencontainers.image.licenses="MIT"
COPY --from=prep --chown=65532:65532 /out/data /data
COPY artifacts/lib/ /app/lib/
COPY artifacts/console.jar /app/console.jar
COPY artifacts/LICENSE artifacts/THIRD-PARTY-NOTICES.md /app/
USER 65532:65532
ENV CONSOLE_DATA=/data CONSOLE_PORT=8443
EXPOSE 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["java", "-jar", "/app/console.jar", "admin", "health"]
# Identity Manager needs nothing mounted: DirXMLDev speaks to the engine over JLDAP. No OpenText code is here.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-cp", "/app/console.jar:/app/lib/*", "com.pointblue.console.server.Main"]
