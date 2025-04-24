#
# Build stage
#
FROM ghcr.io/userver-framework/ubuntu-22.04-userver:latest AS builder

# Copy sources
WORKDIR /app
COPY ./src/ ./

# Build
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make api

#
# Production stage
#
FROM ghcr.io/userver-framework/ubuntu-22.04-userver-base:latest

COPY --from=builder /app/build/api /usr/local/bin/
COPY static_config.yaml /etc/userver-configs/

EXPOSE 8000

CMD ["api", "--config", "/etc/userver-configs/static_config.yaml"]