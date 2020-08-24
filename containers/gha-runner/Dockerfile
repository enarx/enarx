FROM quay.io/enarx/fedora

RUN dnf -y update
RUN dnf -y install iputils

COPY start.sh /root/
CMD /root/start.sh
