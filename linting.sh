#!/bin/bash

SRC="pyeudiw"

autopep8 -r --in-place $SRC
autoflake -r --in-place  --remove-unused-variables --expand-star-imports --remove-all-unused-imports $SRC

flake8 $SRC --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 $SRC --max-line-length 120 --count --statistics

bandit -r -x $SRC/test* $SRC/*

echo -e '\nHTML:'
shopt -s globstar nullglob
for file in `find example -type f  | grep html`
do
  html_lint.py "$file" | awk -v path="file://$PWD/$file:" '$0=path$0' | sed -e 's/: /:\n\t/'
done
