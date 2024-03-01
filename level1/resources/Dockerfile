FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ssh git gcc make gdb ca-certificates python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/longld/peda.git /etc/peda

RUN echo "source /etc/peda/peda.py" >> ~/.gdbinit

RUN pip3 install pwntools
