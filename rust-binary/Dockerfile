
                FROM debian:bullseye@sha256:2c7a92a41cb814c00e7d455b2bc0c90ccdb9a4ced2ffdc10e562c7a84a186032
                RUN apt-get update && apt-get install -y openssh-server gcc make dpkg-dev curl
                RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu --default-toolchain nightly --profile default -y
                RUN /root/.cargo/bin/rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
                WORKDIR /root
                RUN /root/.cargo/bin/cargo init
                COPY Cargo.toml /root/Cargo.toml
                RUN RUSTFLAGS='-Zlocation-detail=none' /root/.cargo/bin/cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release
                WORKDIR /wd
                ENTRYPOINT ["/bin/bash", "-c", "RUSTFLAGS='-Zlocation-detail=none' /root/.cargo/bin/cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release"]
            