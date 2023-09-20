#!/usr/bin/env bash

dockerflag=""
if [ "$1" == "--debug" ]; then
    dockerflag="--build-arg BUILD_MODE=debug"
fi

docker build $dockerflag -f ../Dockerfile -t midhooks ../
container_id=$(docker create midhooks)
docker cp "${container_id}:/project/package/package" .
docker rm ${container_id}
docker image prune -f
