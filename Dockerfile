from quintana/asterisk:latest

# Install Asterisk consul module
WORKDIR /usr/src
RUN git clone https://github.com/sboily/asterisk-consul-module.git
WORKDIR /usr/src/asterisk-consul-module
RUN make
RUN make install
RUN make samples

