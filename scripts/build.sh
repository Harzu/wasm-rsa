cd ./src/rsa_rs
cargo build --target wasm32-unknown-unknown --release | exit 1

cd ../../
if [ ! -d './build' ]
then
  mkdir ./build
  mkdir ./build/browser
  mkdir ./build/nodejs
fi

wasm-bindgen ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --browser --out-dir ./build/browser
wasm-bindgen ./src/rsa_rs/target/wasm32-unknown-unknown/release/rsa_lib.wasm --nodejs --out-dir ./build/nodejs
