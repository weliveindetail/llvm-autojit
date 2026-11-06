FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl gnupg \
    git ninja-build cmake zlib1g-dev libzstd-dev python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | \
    gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-23 main" \
    > /etc/apt/sources.list.d/llvm.list

RUN apt-get update && apt-get install -y \
    clang-23 lld-23 llvm-23-dev libclang-rt-23-dev libc++-23-dev libc++abi-23-dev \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/cc  cc  /usr/bin/clang-23   100 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-23 100 && \
    update-alternatives --install /usr/bin/ld  ld  /usr/bin/ld.lld-23  100 && \
    ln -s /usr/bin/clang-23 /usr/bin/clang

# Noble marks the system Python as externally managed
RUN pip install --break-system-packages lit psutil

WORKDIR /workspace
CMD ["/bin/bash"]
