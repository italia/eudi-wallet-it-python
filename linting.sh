#!/bin/bash

SRC="pyeudiw"
# SRC="example/satosa/integration_test"

autopep8 -r --in-place $SRC
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports $SRC

flake8 $SRC --count --select=E9,F63,F7,F82 --show-source --statistics

# exit-zero treats all errors as warnings. The GitHub editor is 127 chars wide
flake8 $SRC --count --exit-zero --statistics

isort --atomic $SRC

black $SRC

bandit -r -x $SRC/test* $SRC/*

