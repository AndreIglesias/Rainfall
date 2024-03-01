#!/usr/bin/env bash

# Build the Docker image
docker build -t gdb-peda-image .

if [ ! -z "$1" ]; then
    abs_path=$(realpath "$1")
    docker run -it -v "$abs_path":/mnt/binary gdb-peda-image bash -c "gdb -q /mnt/binary"
else
    echo "Usage: ./peda.sh <path_to_binary>"
fi
