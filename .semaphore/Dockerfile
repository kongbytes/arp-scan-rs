FROM rust:1.75.0-slim

# Install SemaphoreCI dependencies
# https://docs.semaphoreci.com/ci-cd-environment/custom-ci-cd-environment-with-docker/
RUN apt-get update && apt-get install -y curl git openssh-client libssl-dev

CMD ["/bin/bash"]
