FROM ubuntu:22.04

RUN apt -y update
RUN apt -y install build-essential
RUN apt -y install cmake
RUN apt -y install git
RUN apt -y install curl
RUN apt -y install python3
RUN apt -y install python3-pip
RUN pip3 install solc-select
RUN solc-select install 0.4.16
RUN cp ~/.solc-select/artifacts/solc-0.4.16/solc-0.4.16 /bin/

git clone --recursive git@github.com:thanhtoantnt/sFuzz.git sfuzz
WORKDIR sfuzz
RUN ./scripts/install_deps.sh
RUN mkdir build
WORKDIR build
RUN cmake ../
WORKDIR fuzzer
RUN cp ../../assets .
RUN make
RUN mkdir output

ENTRYPOINT [ "/bin/bash" ]
