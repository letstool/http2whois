#!/bin/bash

IMAGE_TAG=letstool/http2whois:latest

docker build \
        -t "$IMAGE_TAG" \
       -f build/Dockerfile \
       .
