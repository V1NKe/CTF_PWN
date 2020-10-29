FROM ubuntu:16.04

COPY ./sources.list /etc/apt/
RUN set -eux; apt-get update \
    && apt-get upgrade -y \
    && apt-get install socat -y

RUN useradd -m pwn
WORKDIR /home/pwn
USER pwn
ADD ./pwn.tar.gz /home/pwn
CMD ["/home/pwn/pwn/run.sh"]
