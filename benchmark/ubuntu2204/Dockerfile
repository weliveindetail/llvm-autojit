FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    wget gnupg software-properties-common \
    git ninja-build cmake zlib1g-dev libzstd-dev python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip install lit

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | \
    gpg --dearmor | tee /usr/share/keyrings/llvm-archive-keyring.gpg > /dev/null

RUN echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy-20 main" \
    > /etc/apt/sources.list.d/llvm.list

RUN apt-get update && apt-get install -y \
    clang-20 lld-20 llvm-20-dev libc++-20-dev libc++abi-20-dev libstdc++-12-dev \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/cc  cc  /usr/bin/clang-20   100 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-20 100 && \
    update-alternatives --install /usr/bin/ld  ld  /usr/bin/ld.lld-20  100 && \
    ln -s /usr/bin/clang-20 /usr/bin/clang

WORKDIR /workspace
CMD ["/bin/bash"]
