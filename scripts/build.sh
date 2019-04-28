cd ./src/rsa_rs
cargo build --target wasm32-unknown-unknown --release | exit 1

cd ../../
if [ ! -d './wasm' ]
then
  mkdir ./wasm
  mkdir ./wasm/browser
  mkdir ./wasm/nodejs
fi

$HOME/.cargo/bin/wasm-bindgen ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --browser --out-dir ./wasm/browser
$HOME/.cargo/bin/wasm-bindgen ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --nodejs --out-dir ./wasm/nodejs
