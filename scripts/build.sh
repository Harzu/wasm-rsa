TARGET_DIR="`dirname $0`"
BINDGEN_BIN=$(which wasm-bindgen)
WASM_FILE_PATH="$TARGET_DIR/../src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm"
WASM_BUILD_PATH="$TARGET_DIR/../wasm"

if [ ! -f "$HOME/.cargo/bin/wasm-bindgen" ]; then
  echo "wasm-bindgen is not installed, please install and try again";
  exit 1;
fi

cd "$TARGET_DIR/../src/rsa_rs"
cargo build --target wasm32-unknown-unknown --release | exit 1

cd ../..
if [ ! -d $WASM_BUILD_PATH ]
then mkdir $WASM_BUILD_PATH;
fi

if [ ! -d "$WASM_BUILD_PATH/browser" ]
then mkdir "$WASM_BUILD_PATH/browser";
fi

if [ ! -d "$WASM_BUILD_PATH/nodejs" ]
then mkdir "$WASM_BUILD_PATH/nodejs";
fi

$BINDGEN_BIN $WASM_FILE_PATH --browser --out-dir $WASM_BUILD_PATH/browser
$BINDGEN_BIN $WASM_FILE_PATH --nodejs --out-dir $WASM_BUILD_PATH/nodejs
