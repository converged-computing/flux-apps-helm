FROM ubuntu:24.04
COPY entrypoint.sh /entrypoint.sh 
COPY ./install.sh /opt/actions/install.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
