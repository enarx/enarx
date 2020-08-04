FROM quay.io/enarx/fedora

RUN dnf -y install iputils

COPY setup.sh start.sh /root/
RUN /root/setup.sh
CMD /root/start.sh
