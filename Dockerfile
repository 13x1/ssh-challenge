FROM debian:bullseye@sha256:2c7a92a41cb814c00e7d455b2bc0c90ccdb9a4ced2ffdc10e562c7a84a186032
RUN apt-get update && apt-get install -y openssh-server gcc make dpkg-dev
COPY xz-safe.tar /tmp/xz-safe.tar
ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /flag.txt
ENV PATH="/tmp/xz/bin:${PATH}"
EXPOSE 22
ENTRYPOINT ["/bin/bash", "-c", "\
cd /tmp && \
tar -xf xz-safe.tar && \
cd xz-5* && \
mkdir /tmp/xz/ && \
./configure --prefix=/tmp/xz && \
make && make install && \
chown root /root && chown root /root/.ssh && \
service ssh start && \
bash -i || sleep 1000000 # if we're running interactive you even get a shell! \
"]