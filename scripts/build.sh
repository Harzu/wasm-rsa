BINDGEN_BIN=$(which wasm-bindgen)
TARGET_DIR="`dirname $0`"
WASM_FILE_PATH="$TARGET_DIR/../src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm"
WASM_BUILD_PATH="$TARGET_DIR/../wasm"

if [ ! -f "$HOME/.cargo/bin/wasm-bindgen" ]; then
  echo "wasm-bindgen is not installed, please install and try again";
  exit 1;
fi

cd ./src/rsa_rs
cargo build --target wasm32-unknown-unknown --release | exit 1

cd ../../
if [ ! -d './wasm' ]
then
  mkdir ./wasm
  mkdir ./wasm/browser
  mkdir ./wasm/nodejs
fi

$BINDGEN_BIN $WASM_FILE_PATH --browser --out-dir $WASM_BUILD_PATH/browser
$BINDGEN_BIN $WASM_FILE_PATH --nodejs --out-dir $WASM_BUILD_PATH/nodejs
