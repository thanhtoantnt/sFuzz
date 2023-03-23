FROM ubuntu:22.04

RUN apt -y update
RUN apt -y install build-essential
RUN apt -y install cmake
RUN apt -y install git
RUN apt -y install curl

COPY . sfuzz
WORKDIR sfuzz
RUN ./scripts/install_deps.sh
RUN mkdir build
WORKDIR build
RUN cmake ../
WORKDIR fuzzer
RUN make

ENTRYPOINT [ "/bin/bash" ]
