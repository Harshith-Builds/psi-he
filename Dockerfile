# Clean, pinned build environment: Ubuntu 24.04 + OpenFHE v1.6.1 (built from source) + libsodium.
#   docker build -t psi-he .                                   (first build: ~15-30 min, mostly OpenFHE)
#   docker run --rm -v "$PWD/results:/work/results" psi-he     (full run; add  --quick  for a short one)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake git ca-certificates pkg-config libsodium-dev python3 python3-matplotlib \
    && rm -rf /var/lib/apt/lists/*

ARG OPENFHE_VERSION=v1.6.1
RUN git clone --depth 1 --branch ${OPENFHE_VERSION} https://github.com/openfheorg/openfhe-development.git /opt/openfhe \
    && cmake -S /opt/openfhe -B /opt/openfhe/build -DCMAKE_BUILD_TYPE=Release -DWITH_OPENMP=ON \
         -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
    && cmake --build /opt/openfhe/build -j"$(nproc)" \
    && cmake --install /opt/openfhe/build \
    && rm -rf /opt/openfhe && ldconfig

WORKDIR /work
COPY CMakeLists.txt run.sh ./
COPY src src
COPY apps apps
COPY tests tests
COPY scripts scripts
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
ENTRYPOINT ["./run.sh", "--no-build"]
