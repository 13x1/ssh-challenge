#RUSTFLAGS="-Zlocation-detail=none" cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release
echo `
FROM debian:bullseye
RUN apt-get update && apt-get install -y openssh-server gcc make dpkg-dev curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu --default-toolchain nightly --profile default -y
RUN /root/.cargo/bin/rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
WORKDIR /wd
ENTRYPOINT ["/bin/bash", "-c", "RUSTFLAGS='-Zlocation-detail=none' /root/.cargo/bin/cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release"]
` | save -f Dockerfile
docker build --network=host -t (pwd|path basename) .
docker run -it --network=host -v $"(pwd):/wd" (pwd|path basename)
rm -f target/x86_64-unknown-linux-gnu/release/rust-binary-upx
upx --best --ultra-brute --overlay=strip target/x86_64-unknown-linux-gnu/release/rust-binary -o target/x86_64-unknown-linux-gnu/release/rust-binary-upx
ls target/x86_64-unknown-linux-gnu/release/rust-binary*
