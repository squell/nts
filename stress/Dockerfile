FROM debian:trixie
COPY ./install-dependencies.sh /install
RUN DEBIAN_FRONTEND=noninteractive /install
RUN rm /install
