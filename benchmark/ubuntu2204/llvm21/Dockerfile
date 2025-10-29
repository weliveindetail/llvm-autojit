FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget gnupg software-properties-common \
    git ninja-build cmake zlib1g-dev libzstd-dev python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | \
    gpg --dearmor | tee /usr/share/keyrings/llvm-archive-keyring.gpg > /dev/null

RUN echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-21 main" \
    > /etc/apt/sources.list.d/llvm.list

# Ubuntu clang-21 links LLVM 21.1.5
RUN apt-get update && apt-get install -y \
    clang-21 lld-21 llvm-21-dev libc++-21-dev libc++abi-21-dev libstdc++-12-dev \
    && rm -rf /var/lib/apt/lists/*

# Rust nightly 1.91 links LLVM 21.1.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain nightly-2025-08-11
ENV PATH="/root/.cargo/bin:${PATH}"

RUN update-alternatives --install /usr/bin/cc  cc  /usr/bin/clang-21   100 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-21 100 && \
    update-alternatives --install /usr/bin/ld  ld  /usr/bin/ld.lld-21  100 && \
    ln -s /usr/bin/clang-21 /usr/bin/clang && \
    for bin in rustc cargo rustup; do \
        update-alternatives --install /usr/bin/$bin $bin /root/.cargo/bin/$bin 100; \
    done

RUN pip install lit psutil

WORKDIR /workspace
CMD ["/bin/bash"]
