#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

rsync -r -a -v -e ssh --exclude='.git' --exclude='cmake-build-*' $DIR callisto3:

echo "These files need to be deleted: (may be empty)"
rsync --dry-run --delete -r -a -v -e ssh --exclude='.git' --exclude='cmake-build-*' $DIR callisto3:
# rsync --delete -r -a -v -e ssh --exclude='.git' $DIR callisto3: