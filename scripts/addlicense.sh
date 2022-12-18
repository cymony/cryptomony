#!/bin/bash

if ! command -v addlicense &> /dev/null
then
    echo "addlicense could not be found"
    echo "Run \"go install github.com/google/addlicense@latest\" to install"
else
    SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
    PROJ_DIR=$(dirname $SCRIPT_DIR)
    cd $PROJ_DIR && addlicense -v -l bsd -c "Cymony Authors." $(find . -name "*.go" -type f -print0 | xargs -0)
fi
