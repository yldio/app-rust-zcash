#!/bin/bash

set -e
set -o pipefail

VENDOR_DIR="vendor"

pushd $VENDOR_DIR > /dev/null

# For every submodule, cd into it directory and generate patches
# don't forget to skip the patches directory
for submodule_dir in */ ; do
    [[ "$submodule_dir" == "patches/" ]] && continue
    submodule_name=$(basename "$submodule_dir")
    echo "Generating patch for submodule $submodule_name"
    pushd "$submodule_name" > /dev/null
    # Generate patch and save it to patches directory
    git diff > "../patches/${submodule_name}_dep.patch"
    popd > /dev/null
done

popd > /dev/null