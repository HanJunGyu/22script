#!/bin/bash

eval date -d \'1970-01-01 UTC $1 seconds\' +\"%Y-%m-%d %T %z\"
