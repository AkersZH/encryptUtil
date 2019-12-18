const rsaUtil = require('./rsaUtil')
const aesUtil = require('./aesUtil')
const key = '6453627381726354'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----MIIBOAIBAAJAYesmG1mle69X/8yE0L1A6aAd3G0hWFVXZDCsc9VC8RC9mlWhZ4Gx3w0vYalt1p/6eEb83Ku0mbaMXQYxJQo8JQIDAQABAkABxylL+da9ZjOs22PV/nm9REEGjZy7Y+FQWmnnOIoconFRCz4WmNXFlvop21GD6l4DtTTH8gkc+coFgY1X2EzBAiEAwaMuT3TsLcA4Ehjd1GgSW9MfpMnLdVx+VfbTjPBKZ5kCIQCBdDyW0ov4oJuDgUUQxse4A4vq+OKZzgU6bFAlaVEgbQIgaWyPjSEKaUpK/MdfFwLmY+oJQ22+gRIvklwFB6nXyJkCIDY5tleHAlK3E+1V7NRGL8qI0ccvUdwTTGVYkYnaP71RAiBHOsk1h3eEPKuS3cRuFu80XV7umQVIPBY89i0Y3ZXSAg==-----END RSA PRIVATE KEY-----'
const publicKey = '-----BEGIN PUBLIC KEY-----MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAYesmG1mle69X/8yE0L1A6aAd3G0hWFVXZDCsc9VC8RC9mlWhZ4Gx3w0vYalt1p/6eEb83Ku0mbaMXQYxJQo8JQIDAQAB-----END PUBLIC KEY-----'
const sigPrivateKey = '-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAIk+/zmlb5hOw1c5NQSme9A1PIIXyAmwTUdpdPjMaswSrAde1MVpVfMxe1Lxe44nTFs1siLgcp3edDRjI7vmn2ECAwEAAQJAGnMPkLZ3OS0ErEyUER9cgRWhYZjfri5R1k9WgZQziLxPNAR9IFTUPZH5sOxgXE+MjXcJZQ3zuf/nW5QqSw+NWQIhAN2U/qVI3gWWp2P+mXLEprnK8ov5sM/7nQ+z8byNi+WHAiEAnpB2IlXfGF6u/vz7dYmn9VXGEhevzUf74dthWjl3DdcCIQC7QuH6GZzZKDsK/O392kf1GJjmxvwwqTpRPQf9C7rBHQIgZN1uWG8ZiG4Kkaep6d3UGssiQTYSHdpxjv23kuZFJmcCIAphJ+XAXLjw4OGxqBECC/RDcjQEU59lTqkE0OH5ejlx-----END RSA PRIVATE KEY-----'
const sigPublicKey = '-----BEGIN PUBLIC KEY-----MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIk+/zmlb5hOw1c5NQSme9A1PIIXyAmwTUdpdPjMaswSrAde1MVpVfMxe1Lxe44nTFs1siLgcp3edDRjI7vmn2ECAwEAAQ==-----END PUBLIC KEY-----'
let content = {name: 'xxx'}
console.log('--------------------------------加密过程--------------------------------')
// 1.私钥加签
let sig = rsaUtil.rsaCreateSig(content, sigPrivateKey)
console.log('------------------私钥生成签名：' + sig)
let aesKey = Math.random().toString().slice(-8) + Math.random().toString().slice(-8)
console.log('------------------随机生成对称加密密钥：' + aesKey)
let contentByAes = aesUtil.aesEncipher(content, aesKey)
console.log('------------------对成密钥非对称加密：' + contentByAes)
let aesKeyByRsa = rsaUtil.rsaEncipher(aesKey, publicKey)
let c = {s: sig, k: aesKeyByRsa, c: contentByAes}
console.log('------------------传输密文：', c)

console.log('--------------------------------解密过程--------------------------------')
aesKey = rsaUtil.rsaDecrypt(c.k, privateKey)
console.log('------------------对称密钥非对称解密：' + aesKey)
contentRes = aesUtil.aesDecrypt(c.c, aesKey)
console.log('------------------对称解密结果：' + JSON.stringify(contentRes))
let checkRes = rsaUtil.rsaCheckSig(contentRes, c.s, sigPublicKey)
console.log('------------------签名验证：' + checkRes)

