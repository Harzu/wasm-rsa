const RSASetup = require('wasm-rsa').default

const sign_btn = document.querySelector('#sign')
const verify_btn = document.querySelector('#verify_start')
const create_btn = document.querySelector('#generate_pub')
const generate_btn = document.querySelector('#generate_private')

document.addEventListener('DOMContentLoaded', async () => {
  const rsaOne = await RSASetup()
  const rsaTwo = await RSASetup()
  
  const div_error = document.querySelector('#error')
  const div_private_e = document.querySelector('#private_e')
  const div_private_d = document.querySelector('#private_d')
  const div_private_n = document.querySelector('#private_n')

  const div_public_e = document.querySelector('#pub_e')
  const div_public_n = document.querySelector('#pub_n')

  const div_signature = document.querySelector('#sign_mess')
  const div_verify_result = document.querySelector('#verify_result')

  // Start listeners
  generate_btn.addEventListener('click', event => {
    event.preventDefault()
    try {
      const keys = rsaOne.generateRSAPrivate(1024)
      div_private_e.textContent = `e_${keys.e}`
      div_private_d.textContent = `d_${keys.d}`
      div_private_n.textContent = `n_${keys.n}`
    } catch (error) {
      div_error.textContent = error
    }
  })

  create_btn.addEventListener('click', event => {
    event.preventDefault()

    const e = div_private_e.textContent.split('_')[1]
    const n = div_private_n.textContent.split('_')[1]

    try {
      const keys = rsaTwo.createRSAPublic(n, e)
      div_public_e.textContent = `e_${keys.e}`
      div_public_n.textContent = `n_${keys.n}`
    } catch (error) {
      div_error.textContent = error
    }
  })

  sign_btn.addEventListener('click', event => {
    event.preventDefault()
    const message = document.querySelector('#inp_message')

    try {
      const signature = rsaOne.signMessage(message.value)
      div_signature.textContent = `signature_${signature}`
    } catch (error) {
      div_error.textContent = error
    }
  })

  verify_btn.addEventListener('click', event => {
    event.preventDefault()

    const verify_message = document.querySelector('#inp_verify_mess')
    const verify_signature = document.querySelector('#inp_verify_sign')

    try {
      const verify = rsaTwo.verify(verify_message.value, verify_signature.value)
      if (verify) {
        div_verify_result.textContent = 'Success'
      }
    } catch (error) {
      div_verify_result.textContent = ''
      div_error.textContent = error
    }
  })
})

