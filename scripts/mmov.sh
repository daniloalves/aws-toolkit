#!/bin/bash

sleep_time=${1:-30}  # Set the sleep time in seconds, default to 30 if not provided
timeout=$((3 * 60 * 60))  # 4 hours in seconds
start_time=$(date +%s)

while true; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))
  if [ $elapsed -ge $timeout ]; then
    echo "Timeout of 3 hours reached. Exiting."
    break
  fi
  sleep $sleep_time && xdotool mousemove 10 55
done