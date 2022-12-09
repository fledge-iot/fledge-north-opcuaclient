#!/usr/bin/env bash

ARCHITECTURE=$(arch)

if [ ${ARCHITECTURE} = "armv7l" ]; then
    apt install -y libssl-dev
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh /dev/stdin -y
    echo "BEFORE: PATH: "$PATH
    . "$HOME/.cargo/env"
    echo "AFTER: PATH: "$PATH
    rustc --version
fi
