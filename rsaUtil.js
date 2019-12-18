var RSA = require('./wx_rsa.js')

module.exports = {
  rsaEncipher (context, key) {
    let encrypt_rsa = new RSA.RSAKey()
    encrypt_rsa = RSA.KEYUTIL.getKey(key)
    let encStr = encrypt_rsa.encrypt(context)
    encStr = RSA.hex2b64(encStr)
    return encStr
  },
  rsaDecrypt (context, key) {
    let decrypt_rsa = new RSA.RSAKey()
    decrypt_rsa = RSA.KEYUTIL.getKey(key)
    let encStr = RSA.b64tohex(context)
    let decStr = decrypt_rsa.decrypt(encStr)
    return decStr
  },
  rsaCreateSig (context, key) {
    let sign_rsa = new RSA.RSAKey()
    sign_rsa = RSA.KEYUTIL.getKey(key)
    let hashAlg = 'sha1'
    Sig = sign_rsa.signString(JSON.stringify(context), hashAlg)
    Sig = RSA.hex2b64(Sig)
    return Sig
  },
  rsaCheckSig (context, Sig, key) {
    let verify_rsa = new RSA.RSAKey()
    verify_rsa = RSA.KEYUTIL.getKey(key)
    Sig = RSA.b64tohex(Sig)
    let ver = verify_rsa.verifyString(JSON.stringify(context), Sig)
    return ver
  }
}
