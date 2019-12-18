const crypto = require('./aes')

module.exports = {
  aesEncipher (context, key) {
    key = crypto.enc.Utf8.parse(key)
    let iv = crypto.enc.Utf8.parse(key)
    context = JSON.stringify(context)
    var srcs = crypto.enc.Utf8.parse(context)
    var encrypted = crypto.AES.encrypt(srcs, key,
      {
        iv: iv,
        mode: crypto.mode.CBC,
        padding: crypto.pad.Pkcs7
      })
    return encrypted.ciphertext.toString(crypto.enc.Base64)
  },
  
  aesDecrypt (context, key) {
    key = crypto.enc.Utf8.parse(key)
    let iv = crypto.enc.Utf8.parse(key)
    var decrypted = crypto.AES.decrypt(context.toString(crypto.enc.Base64), key,
      {
        iv: iv,
        mode: crypto.mode.CBC,
        padding: crypto.pad.Pkcs7
      })
    let res = decrypted.toString(crypto.enc.Utf8)
    return JSON.parse(res)
  }
}
