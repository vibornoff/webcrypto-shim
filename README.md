webcrypto-shim.js
=================

[Web Cryptography API](www.w3.org/TR/WebCryptoAPI/) shim for legacy browsers.

Quick start with _Bower_
------------------------

Install the package

```sh
$ bower install webcrypto-shim
```

and link scripts into your html code

```html
<script src="bower_components/promiz/promiz.js"></script>
<script src="bower_components/webcrypto-shim/webcrypto-shim.js"></script>
```

Now you can use webcrypto api through the `window.crypto` and `window.crypto.subtle` objects.

Note that _IE11_ lacks support of `Promise`-s and requires _promiz.js_ to work properly. You can replace _promiz.js_ with any _Promise/A+_-compatible implementation.

Supported browsers
------------------

The library is targeted to fix these browsers having prefixed and buggy webcrypto api implementations:
* _Internet Explorer 11_, _Mobile Internet Explorer 11_,
* _Safari 8+_, _iOS Safari 8+_.

These browsers have unprefixed and conforming webcrypto api implementations, so no need in shim:
* _Chrome 43+_, _Chrome for Android 44+_,
* _Opera 24+_,
* _Firefox 34+_,
* _Edge 12+_.

Supported algorithms & operations
---------------------------------

* **SHA-256**, **SHA-384**: `digest`
  * _IE11_ doesn't support **SHA-1**, though [doc claims](https://msdn.microsoft.com/en-us/library/dn302338\(v=vs.85\).aspx) it should work

* **HMAC** (with hash: **SHA-1**, **SHA-256**, **SHA-384**): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`
  * importing `"jwk"` key for **HMAC\_SHA-1** fails

* **AES-CBC**: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`

* **AES-GCM**: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  *  _Safari_ doesn't support **AES-GCM**
  * _IE11_ requires `iv` parameter length must be exactly _96_ bits (_12_ octets)

* **AES-KW**: `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _TODO_ tests

* **RSASSA-PKCS1-v1\_5** (with hash: **SHA-256**, **SHA-384**): `sign`, `verify`, `generateKey`, `importKey`, `exportKey`
  * under _IE11_ only `generateKey` and `exportKey` work with **SHA-1** hash

* **RSAES-PKCS1-v1\_5**: `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * only _IE11_ and _Safari_ support this algorithm
  * _TODO_ tests

* **RSA-OAEP** (with hash/MGF1: **SHA-1**, **SHA-256**): `encrypt`, `decrypt`, `generateKey`, `importKey`, `exportKey`, `wrapKey`, `unwrapKey`
  * _Safari_ supports this algorithm only with **SHA-1** hash
  * _TODO_ tests

Known limitations
-----------------

`deriveKey`, `deriveBits` are not supported under _IE11_ and _Safari_  since there is no implementation of any algorithm providing key derivation.

_IE11_ silently discards empty input leaving returned `Promise` object in pending state.

_Safari_ prevents RSA keys of size smaller than 2048 bits to be imported/exported.

Other browsers support
----------------------

See https://vibornoff.github.io/webcrypto-examples/index.html
