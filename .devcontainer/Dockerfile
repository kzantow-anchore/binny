ARG PYTHON_VERSION="3.13"

FROM python:${PYTHON_VERSION}-slim

ARG GO_VERSION="1.25.9"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    zsh \
    git \
    ssh \
    make \
    curl \
    jq \
    ncurses-bin \
    && rm -rf /var/lib/apt/lists/*

RUN adduser dev

USER dev

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ARG INSTALL_CLAUDE=""
RUN if [ -n "$INSTALL_CLAUDE" ]; then \
  curl -fsSL https://claude.ai/install.sh | bash; \
fi

RUN curl -LsSf https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /home/dev

ENV PATH="/home/dev/go/bin:$PATH"
ENV GOPATH="/home/dev"
ENV GOROOT="/home/dev/go"
ENV GOMODCACHE="$GOROOT/pkg/mod"

# for debugging
RUN go install github.com/go-delve/delve/cmd/dlv@latest

RUN echo "\n . /home/dev/.init_binny" >> /home/dev/.bashrc
RUN echo "\n . /home/dev/.init_binny \n PROMPT='%n@%m %~ %# '" >> /home/dev/.zshrc

# setup binny to run authenticated commands
RUN echo "cp /binny/.binny.yaml /home/dev/.binny.yaml \n . /binny/.devcontainer/env.sh \n alias dir='ls -alFh --color'" >> /home/dev/.init_binny
ENV GH_SPINNER_DISABLED=1
ENV GH_PROMPT=disabled
ENV GH_PAGER=""

CMD ["bash"]
