const crypto = require('../index.js')

const nonce = crypto.randomBytes()
crypto(nonce)

const { publicKey: pk, secretKey: sk } = crypto.generateKeypair()

const trySigning = (toSign, shouldSign) => {
  console.log(`Trying to sign: ${JSON.stringify(toSign)}`)
  console.log(`Should sign: ${shouldSign}`)
  let signed
  try {
    crypto.signObj(toSign, sk, pk)
    console.log('=== Sign Successful ===')
    console.log('Result of sign:')
    console.log(toSign)
    signed = true
  } catch (e) {
    console.log('=== Sign Failed ===')
    console.error(e)
    signed = false
  }
  console.log('====================')
  if (shouldSign === signed) {
    console.log('Test passed.')
    console.log()
    return true
  } else {
    console.log('Test failed.')
    console.log()
    return false
  }
}

const testSigningObjWithProps = () => {
  const objWithProps = { prop: true }
  return trySigning(objWithProps, true)
}

const testSigningObjWithoutProps = () => {
  const objWithoutProps = {}
  return trySigning(objWithoutProps, true)
}

const testSigningArrWithItems = () => {
  const arrWithItems = ['item1', 'item2']
  return trySigning(arrWithItems, false)
}

const testSigningArrWithoutItems = () => {
  const arrWithoutItems = []
  return trySigning(arrWithoutItems, false)
}

const test = () => {
  const results = []
  results.push(testSigningObjWithProps())
  results.push(testSigningObjWithoutProps())
  results.push(testSigningArrWithItems())
  results.push(testSigningArrWithoutItems())

  let passed = 0
  for (const result of results) {
    if (result) {
      passed += 1
    }
  }
  const total = results.length
  console.log(`${passed}/${total} tests passed.`)
}

test()
