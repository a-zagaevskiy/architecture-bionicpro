#
# Build stage
#
FROM ghcr.io/userver-framework/ubuntu-22.04-userver:latest AS builder

# Build jwt-cpp
RUN git clone https://github.com/Thalhammer/jwt-cpp.git
RUN cd jwt-cpp && \
    cmake -DJWT_BUILD_EXAMPLES=OFF -DJWT_BUILD_TESTS=OFF . && \
    cmake --build . && \
    cmake --install .

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