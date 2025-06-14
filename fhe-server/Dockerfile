# Use Ubuntu 24.04 as the base image
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# -----------------------------------------------------------------------------
# Install system dependencies: build tools, CMake, Git, autoconf, libtool, Boost, GMP, OpenSSL, Python, wget, FFTW
# -----------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    autoconf \
    libtool \
    libboost-all-dev \
    libgmp-dev \
    # libntl-dev \ # Removed - Will build from source
    libssl-dev \
    python3 \
    python3-pip \
    inotify-tools \
    wget \
    libfftw3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Set working directory and copy project source (needed for submodules)
# -----------------------------------------------------------------------------
WORKDIR /app
COPY . /app



# -----------------------------------------------------------------------------
# Build and Install NTL from Source (Dependency for HElib)
# -----------------------------------------------------------------------------
ARG NTL_VERSION="11.5.1" # Check for latest stable NTL version
RUN cd /tmp && \
    wget "https://libntl.org/ntl-${NTL_VERSION}.tar.gz" && \
    tar -xzf "ntl-${NTL_VERSION}.tar.gz" && \
    cd "ntl-${NTL_VERSION}/src" && \
    ./configure PREFIX=/usr/local NTL_GMP_LIP=on NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on && \
    make -j$(nproc) && \
    make install SHARED=on && \
    cd / && rm -rf /tmp/ntl-${NTL_VERSION}*

# -----------------------------------------------------------------------------
# Build and Install HElib from Submodule (Uses NTL/GMP from /usr/local)
# -----------------------------------------------------------------------------
RUN cd /app/src/thirdparty/HElib && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=RelWithDebInfo \ 
          -DBUILD_SHARED_LIBS=ON \          
          -DENABLE_THREADS=ON && \          
    cmake --build build -j$(nproc) && \
    cmake --install build
# -----------------------------------------------------------------------------
# Build and Install SEAL from Submodule
# -----------------------------------------------------------------------------
RUN cd /app/src/thirdparty/SEAL && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
          -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF && \
    cmake --build build -j$(nproc) && \
    cmake --install build

# -----------------------------------------------------------------------------
# Build and Install TFHE from Submodule (Uses FFTW from /usr)
# -----------------------------------------------------------------------------
RUN cd /app/src/thirdparty/tfhe && \
    cmake -S src -B build \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_BUILD_TYPE=Release \ 
          -DENABLE_SHARED=ON \
          -DENABLE_FFTW=ON \
          -DENABLE_SPQLIOS_AVX=ON -DENABLE_SPQLIOS_FMA=ON && \ 
    cmake --build build -j$(nproc) && \
    cmake --install build

# -----------------------------------------------------------------------------
# Build and Install M4RI from Submodule (Uses autotools)
# -----------------------------------------------------------------------------
RUN cd /app/src/thirdparty/m4ri && \
    autoreconf --install && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# -----------------------------------------------------------------------------
# Build and Install Paho MQTT Libraries (Example - keep if needed)
# -----------------------------------------------------------------------------
RUN git clone --branch v1.3.14 --depth 1 https://github.com/eclipse-paho/paho.mqtt.c.git /tmp/paho.mqtt.c && \
    cd /tmp/paho.mqtt.c && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DPAHO_BUILD_SHARED=ON -DPAHO_WITH_SSL=ON && \
    cmake --build build -j$(nproc) && cmake --install build && \
    cd / && rm -rf /tmp/paho.mqtt.c

RUN git clone --branch v1.5.2 --depth 1 https://github.com/eclipse-paho/paho.mqtt.cpp.git /tmp/paho.mqtt.cpp && \
    cd /tmp/paho.mqtt.cpp && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DPAHO_BUILD_SHARED=ON -DPAHO_WITH_SSL=ON && \
    cmake --build build -j$(nproc) && cmake --install build && \
    cd / && rm -rf /tmp/paho.mqtt.cpp

# -----------------------------------------------------------------------------
# Update linker cache and optional cleanup
# -----------------------------------------------------------------------------
RUN ldconfig
# Optional: Remove build directories from submodules to save space
# RUN rm -rf /app/src/thirdparty/*/build /app/src/thirdparty/m4ri/installed /app/src/thirdparty/tfhe/installed

# -----------------------------------------------------------------------------
# Set final working directory and default command
# -----------------------------------------------------------------------------
WORKDIR /app
# CMD will execute watch_build.sh, which should now ONLY run cmake/make for YOUR project
CMD ["./watch_build.sh"]