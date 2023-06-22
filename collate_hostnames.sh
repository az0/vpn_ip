#!/bin/sh

# sed remove comments and empty lines
cat data/input/hostname_*/*txt | sed '/^[ \t]*#/d' | sed  '/^$/d' > data/output/hostname.txt
