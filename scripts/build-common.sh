#!/bin/bash

cd ${0%/*}
cd ..

yarn clean
yarn install
yarn build-js

# Update commit hash in package.json
COMMIT_HASH=$(git rev-parse HEAD)

# print commit hash
echo "Commit hash: ${COMMIT_HASH}"

sed -i '' '/"commit":.*,/d' package.json && sed -i '' '4 i \
  "commit": "'${COMMIT_HASH}'",\
' package.json