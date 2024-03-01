#!/usr/bin/env bash

if [ ! -z "$1" ]; then
    abs_path=$(realpath "$1")
    docker run -it -v "$abs_path":/mnt/binary radare/radare2 bash -c "sudo /snap/radare2/current/bin/r2 /mnt/binary"
else
    echo "Usage: ./radare2.sh <path_to_binary>"
fi
