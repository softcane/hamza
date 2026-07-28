# --- Build stage: the build gate. `docker build .` runs `mvn verify` here. ---
# No local JDK/Maven is assumed; everything builds in this container.
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app

# Cache dependencies separately from source so code changes don't refetch the world.
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -B -q dependency:go-offline

COPY CONTEXT.md README.md ./
COPY quality ./quality
# The M3 approved Presidio profile is a build input: the detector contract tests load
# it to prove that only an approved entity can ever enforce.
COPY detector ./detector
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B verify

# --- Runtime stage: slim JRE, no Maven, no build tooling. ---
FROM eclipse-temurin:25-jre AS runtime
WORKDIR /app

# curl is used by the Compose healthcheck against /actuator/health.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user; /data holds the SQLite Record store.
RUN groupadd --system --gid 10001 hamza \
    && useradd --system --uid 10001 --gid hamza --home-dir /nonexistent --shell /usr/sbin/nologin hamza \
    && mkdir -p /data && chown hamza:hamza /data
VOLUME ["/data"]
USER hamza

COPY --from=build /app/target/hamza-core-*.jar /app/app.jar

# 8080 = actuator/management HTTP; 9090 = ext_proc gRPC (Envoy connects here).
EXPOSE 8080 9090

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
