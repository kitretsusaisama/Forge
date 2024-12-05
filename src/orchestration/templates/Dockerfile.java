# Java Development Dockerfile
FROM openjdk:17-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Copy Maven project files
COPY pom.xml .
COPY src ./src

# Download dependencies
RUN mvn dependency:go-offline

# Build the application
RUN mvn clean package -DskipTests

# Expose default port
EXPOSE 8080

# Set environment variables
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0"

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# Run application
CMD ["java", "-jar", "/app/target/app.jar"]
