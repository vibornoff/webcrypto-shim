mscrypto-adapter.js
===================

Web Cryptography API adapter

Quick start with Bower
----------------------

Install the package

```sh
$ bower install mscrypto-adapter
```

add add scripts into your html code

```html
<script src="bower_components/promiz/promiz.js"></script>
<script src="bower_components/mscrypto-adapter/mscrypto-adapter.js"></script>
```

Now you can access [Web Crypto API](www.w3.org/TR/WebCryptoAPI/) through the `window.crypto` object.

Also you can replace _promiz.js_ with any _Promise/A+_-compatible `Promise` implementation.

Supported algorithms & operations
---------------------------------

* _SHA-256_, _SHA-384_: `digest`

  * _empty input isn't allowed and causes an error_

  * _SHA-1_ isn't supported, though [doc claims](https://msdn.microsoft.com/en-us/library/dn302338(v=vs.85).aspx) it should work

* _HMAC_ (with hash: _SHA-1_, _SHA-256_, _SHA-384_): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`

  * _empty input isn't allowed and causes an error_

  * importing `"jwk"` key for _HMAC\_SHA-1_ fails

  * `generateKey` ignores `"length"` parameter, generated key is always of the same length as _HMAC_ output

* _AES-CBC_: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

  * _empty input isn't allowed and causes an error_

* _AES-GCM_: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

  * _empty input isn't allowed and causes an error_

  * `iv` parameter length must be exactly _96_ bits (_12_ octets)

* _AES-KW_: `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

  * _empty input isn't allowed and causes an error_

  * wrapped content length is required to be a multiple of _64_ bits (_8_ octets)

  * **TODO** tests

* _RSA-OAEP_ (with hash/MGF1: _SHA-1_, _SHA-256_, _SHA-384_): `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

  * _empty input isn't allowed and causes an error_

  * **TODO** tests

* _RSASSA-PKCS1-v1\_5_ (with hash: _SHA-1_, _SHA-256_, _SHA-384_): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`

  * _empty input isn't allowed and causes an error_

  * **TODO** tests

* _RSAES-PKCS1-v1\_5_ (with hash: _SHA-1_, _SHA-256_, _SHA-384_): `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

  * _empty input isn't allowed and causes an error_

  * **TODO** tests

Other browsers support
----------------------

See (https://vibornoff.github.io/mscrypto-adapter/webcrypto-examples/)
