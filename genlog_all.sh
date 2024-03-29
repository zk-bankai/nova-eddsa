#!/bin/bash
iters=(8 16 32 64 128)
for i in "${iters[@]}"
do
    echo "Generating output logs for $i iterations"
    command ./target/release/examples/verify $i > ./logs/output_$i.txt
    echo "Sleeping for 1 mins to give the CPU a break"
    sleep 60
done
echo "See logs directory for output files"
