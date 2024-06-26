FROM debian:bookworm as builder
ARG CONAN_VERSION=2.2.2
# hadolint ignore=DL3005,DL3008,DL3047
RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install cmake make clang binutils git wget ca-certificates \
                    build-essential pipx --no-install-recommends -y && \
    git clone https://github.com/conan-io/conan.git conan-io && \
    git clone https://github.com/WiFiBeat/elasticbeat-cpp && \
    git clone https://github.com/WiFiBeat/simplejson-cpp
WORKDIR /conan-io
RUN git checkout tags/${CONAN_VERSION} && \
    pipx install -e .
COPY . /wifibeat
WORKDIR /wifibeat
RUN export PATH="$PATH:/root/.local/bin" && \
    conan profile detect --force && \
    conan install . --output-folder=build --build=missing
WORKDIR /wifibeat/build
RUN CMAKE_BUILD_TYPE=Release CMAKE_PREFIX_PATH="$(pwd)/build/Release/generators/" cmake .. && \
    make VERBOSE=1 && \
    strip wifibeat

FROM debian:bookworm as final
# hadolint ignore=DL3005,DL3008
RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install man-db -y --no-install-recommends && \
    mkdir -p /usr/local/share/man/man1 && \
    rm -rf man && mkdir man && \
    apt-get autoclean && \
	rm -rf /var/lib/dpkg/status-old /var/lib/apt/lists/* 
COPY --from=builder /wifibeat/build/wifibeat /usr/local/bin/wifibeat
COPY --from=builder /wifibeat/wifibeat.yml /etc
COPY --from=builder /wifibeat/manpages/wifibeat.1 /usr/local/share/man/man1/
RUN wifibeat --help
