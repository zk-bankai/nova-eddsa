#!/bin/bash
iters=(2 10 50 100 150 200)
for i in "${iters[@]}"
do
    echo "Generating output logs for $1 iterations"
    command ./target/release/examples/verify $1 > ./logs/output_$1.txt
    echo "Sleeping for 1 mins to give the CPU a break"
    sleep 60
done
echo "See logs directory for output files"