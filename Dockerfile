FROM ubuntu

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y python3 python3-pip

RUN pip3 install cryptography pyyaml bson

RUN apt-get install -y net-tools

RUN apt-get install -y git make

RUN git clone https://github.com/jech/babeld.git

RUN cd babeld && make && make install
