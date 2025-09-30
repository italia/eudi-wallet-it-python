#!/bin/bash

sphinx-apidoc -o docs/rst pyeudiw
cd docs
make html