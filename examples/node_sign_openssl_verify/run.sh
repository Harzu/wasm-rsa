#!/bin/bash

# Step 1. NodeJS (wasm-rsa) create keys and use it for create signature with message in ./message.txt
node ./sign.js

# Step 2. Check files created
if [[ -f "./private.pem" ]] && [[ -f "./public.pem" ]] && [[ -f "./signature.txt" ]]; then
  # Step 3. Generate binary file from text signature for opessl veirfy
  cat './signature.txt' | sed -e 's/.*= \([^ ]\+\)$/\1/' | xxd -r -p > signature.bin
  # Step 4. Verify
  openssl dgst -sha256 -verify ./public.pem -signature signature.bin message.txt
else
  echo "something wrong"
  exit 225
fi