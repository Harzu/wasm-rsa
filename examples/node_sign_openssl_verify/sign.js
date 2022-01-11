const RSASetup = require('wasm-rsa')
const fs = require("fs")

async function main() {
  firstInstance = await RSASetup.default()
  secondInstance = await RSASetup.default()

  const private_keys = firstInstance.generateRSAPrivate(2048)
  secondInstance.createRSAPublic(private_keys.n, private_keys.e)

  fs.writeFileSync("./private.pem", firstInstance.privateKeyToPEM())
  fs.writeFileSync("./public.pem", secondInstance.publicKeyToPEM())

  const message = fs.readFileSync("./message.txt").toString()
  const signature = firstInstance.signMessage(message)
  fs.writeFileSync("./signature.txt", signature)
}

main()