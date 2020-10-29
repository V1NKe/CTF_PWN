FROM ubuntu:16.04

#ADD ./pwnshell /bin/
RUN useradd pwn
RUN mkdir /home/pwn
COPY ./flag/flag /home/pwn
COPY ./flag/pwn /home/pwn
COPY ./flag/start.sh /home/pwn
RUN chmod +x /home/pwn/start.sh
RUN chown -R pwn:pwn /home/pwn
RUN setcap cap_setgid,cap_setuid+ep /home/pwn/pwn
RUN setcap cap_setgid,cap_setuid+ep /bin/bash


#RUN cp /bin/bash /bin/bash.rescue
#RUN cp /bin/sh /bin/sh.rescue

RUN cp /etc/apt/sources.list /etc/apt/sources.list.backup      
RUN rm -f /etc/apt/sources.list
ADD ./sources.list.16.04 /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y socat

RUN setcap cap_setuid,cap_setgid+ep /usr/bin/socat
#RUN /bin/bash

WORKDIR /home/pwn

#RUN cp -f /bin/pwnshell /bin/bash
#RUN cp -f /bin/pwnshell /bin/sh

USER pwn

#CMD ["/bin/bash", "start.sh"]
