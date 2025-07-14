#!/bin/bash

PROXY="socks5h://127.0.0.1:1080"
URL="https://httpbin.org/get"
CONCURRENCES=20

for i in $(seq 1 $CONCURRENCES); do
  curl -x $PROXY $URL --max-time 10 --silent --output /dev/null &
done

wait
echo "Finalizado."
