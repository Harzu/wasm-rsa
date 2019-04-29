BINDGEN_BIN=$(which wasm-bindgen)

if [ $BINDGEN_BIN == "" ]; then
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

$BINDGEN_BIN ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --browser --out-dir ./wasm/browser
$BINDGEN_BIN ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --nodejs --out-dir ./wasm/nodejs
