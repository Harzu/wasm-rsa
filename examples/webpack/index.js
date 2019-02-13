const RSA = require('wasm-rsa').default


async function run () {
  const rsa = new RSA()
  await rsa.init()
  
  console.log(rsa)
  const keys = rsa.generateRSAPrivate(1024)
  console.log(keys)
}

run()
