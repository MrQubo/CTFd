FROM python:2.7-alpine
RUN apk update && \
    apk add python python-dev linux-headers libffi-dev gcc make musl-dev py-pip mysql-client git openssl-dev
RUN adduser -D -u 1001 -s /bin/bash ctfd

EXPOSE 8000

WORKDIR /opt/CTFd
RUN mkdir -p /opt/CTFd /var/log/CTFd /var/uploads
RUN chown -R 1001:1001 /var/log/CTFd /var/uploads

COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

ENTRYPOINT ["/opt/CTFd/docker-entrypoint.sh"]
COPY ./docker-entrypoint.sh /opt/CTFd/docker-entrypoint.sh
RUN chmod +x /opt/CTFd/docker-entrypoint.sh

COPY ./CTFd/plugins /opt/CTFd/CTFd/plugins
RUN for d in /opt/CTFd/CTFd/plugins/*; do \
      if [ -f "$d/requirements.txt" ]; then \
        pip install -r $d/requirements.txt; \
      fi; \
    done;

COPY . /opt/CTFd
RUN chown -R 1001:1001 /opt/CTFd

USER 1001
