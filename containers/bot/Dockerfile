FROM alpine:edge

RUN apk update

RUN apk add git

RUN apk add nginx
RUN rm -f /etc/nginx/conf.d/default.conf
COPY github.conf /etc/nginx/conf.d/github.conf

RUN apk add py3-deprecated
RUN apk add py3-wrapt
RUN apk add py3-jwt
RUN apk add py3-pip
RUN pip3 install pygithub
