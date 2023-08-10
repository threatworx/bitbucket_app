FROM threatworx/twigs:latest
  
MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

#SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
COPY requirements.txt /tmp
COPY . /usr/share/bitbucket_app
RUN apt-get update && apt-get install -y libssl-dev
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/local/bin/run-app.sh"]
