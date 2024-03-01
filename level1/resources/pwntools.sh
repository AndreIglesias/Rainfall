#!/usr/bin/env bash

# Build the Docker image
docker build -t pwn-peda-image .

if [ ! -z "$1" ]; then
    abs_path=$(realpath "$1")
    docker run --network host -it -v "$abs_path":/mnt/exploit.py pwn-peda-image bash -c "/bin/python3 /mnt/exploit.py"
else
    echo "Usage: ./pwntools.sh <path_to_binary>"
fi
