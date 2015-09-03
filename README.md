mscrypto-adapter.js
===================

Web Cryptography API adapter for _Internet Explorer 11_

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

Also you can replace _promiz.js_ with any _Promise/A+_-compatible implementation.

Supported algorithms & operations
---------------------------------

* **SHA-256**, **SHA-384**: `digest`
  * _empty input isn't allowed and causes an error_
  * **SHA-1** isn't supported, though [doc claims](https://msdn.microsoft.com/en-us/library/dn302338(v=vs.85).aspx) it should work

* **HMAC** (with hash: **SHA-1**, **SHA-256**, **SHA-384**): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`
  * _empty input isn't allowed and causes an error_
  * importing `"jwk"` key for **HMAC\_SHA-1** fails

* **AES-CBC**: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _empty input isn't allowed and causes an error_

* **AES-GCM**: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _empty input isn't allowed and causes an error_
  * `iv` parameter length must be exactly _96_ bits (_12_ octets)

* **AES-KW**: `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _empty input isn't allowed and causes an error_
  * wrapped content length is required to be a multiple of _64_ bits (_8_ octets)
  * _TODO_ tests

* **RSA-OAEP** (with hash/MGF1: **SHA-1**, **SHA-256**, **SHA-384**): `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _empty input isn't allowed and causes an error_
  * _TODO_ tests

* **RSASSA-PKCS1-v1\_5** (with hash: **SHA-1**, **SHA-256**, **SHA-384**): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`
  * _empty input isn't allowed and causes an error_
  * _TODO_ tests

* **RSAES-PKCS1-v1\_5** (with hash: **SHA-1**, **SHA-256**, **SHA-384**): `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _empty input isn't allowed and causes an error_
  * _TODO_ tests

Known limitations
-----------------

`deriveKey`, `deriveBits` are not supported since there is no algorithm providing key derivation operation.

Other browsers support
----------------------

See https://vibornoff.github.io/webcrypto-examples/index.html
