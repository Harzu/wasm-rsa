#! /bin/bash

TARGET_DIR="`dirname $0`"
CRATE_PATH="$TARGET_DIR/.."
BINDGEN_BIN=$(which wasm-pack)
WASM_BUILD_PATH="$CRATE_PATH/wasm"

if [ ! -f "$HOME/.cargo/bin/wasm-pack" ]; then
  echo "wasm-pack is not installed, please install and try again";
  exit 1;
fi

if [ ! -d $WASM_BUILD_PATH ]; then mkdir $WASM_BUILD_PATH; fi
if [ ! -d "$WASM_BUILD_PATH/browser" ]; then mkdir "$WASM_BUILD_PATH/browser"; fi
if [ ! -d "$WASM_BUILD_PATH/nodejs" ]; then mkdir "$WASM_BUILD_PATH/nodejs"; fi

$BINDGEN_BIN build --release --target browser --out-dir $WASM_BUILD_PATH/browser $CRATE_PATH
$BINDGEN_BIN build --release --target nodejs --out-dir $WASM_BUILD_PATH/nodejs $CRATE_PATH

rm -rf $WASM_BUILD_PATH/browser/.gitignore $WASM_BUILD_PATH/browser/package.json $WASM_BUILD_PATH/browser/README.md
rm -rf $WASM_BUILD_PATH/nodejs/.gitignore $WASM_BUILD_PATH/nodejs/package.json $WASM_BUILD_PATH/nodejs/README.md