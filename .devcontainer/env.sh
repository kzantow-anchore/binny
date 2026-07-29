#!/bin/bash

TOOLS_ROOT="$HOME/tools"
mkdir -p "$TOOLS_ROOT"

for name in gh docker oras; do
    echo "binny run '$name' \"\$@\"" > "$TOOLS_ROOT/$name"
    chmod +x "$TOOLS_ROOT/$name"
done

export PATH="$TOOLS_ROOT:$PATH"

# so binny will put it's tools in a shared location
export BINNY_ROOT="$HOME/.tool"
mkdir -p "$BINNY_ROOT"

# build and set up binny itself

this_script="$0"
if [ -n "$BASH_SOURCE" ]; then
  this_script=$BASH_SOURCE
elif [ -n "$ZSH_VERSION" ]; then
  setopt function_argzero
  this_script=$0
elif eval '[[ -n ${.sh.file} ]]' 2>/dev/null; then
  eval 'this_script=${.sh.file}'
else
  echo 1>&2 "Unsupported shell. Please use bash, ksh93 or zsh."
  exit 2
fi

pushd "$(dirname $this_script)/.."

if [ -z .devcontainer/env.sh ]; then
  echo 1>&2 "Unable to determine binny path"
  exit 2
fi

rm -f "$TOOLS_ROOT/binny"
go build -o "$TOOLS_ROOT/binny" ./cmd/binny
popd

# by default claude captures both stderr and stdout and does a bunch of stuff to work around this so suppress these logs
export BINNY_LOG_QUIET=true
