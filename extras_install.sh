#!/usr/bin/env bash

ARCHITECTURE=$(arch)

if [ ${ARCHITECTURE} = "armv7l" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh /dev/stdin -y
    . "$HOME/.cargo/env"
fi
