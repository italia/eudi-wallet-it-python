#!/bin/bash

SRC="pyeudiw"

autopep8 -r --in-place $SRC
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports $SRC

flake8 $SRC --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 $SRC --max-line-length 120 --count --statistics

bandit -r -x $SRC/test* $SRC/*
