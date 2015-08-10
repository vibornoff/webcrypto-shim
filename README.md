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
<script src="bower_components/setImmediate/setimmediate.js"></script>
<script src="bower_components/promise-polyfill/Promise.js"></script>
<script src="bower_components/mscrypto-adapter/mscrypto-adapter.js"></script>
```

Now you can access [Web Crypto API](www.w3.org/TR/WebCryptoAPI/) through `window.crypto` object.

Bugs and Limitations
--------------------

 * *Crypto operation on an empty buffer never returns result*.

 * No *SHA-1* support for `digest`, though [Doc claims](https://msdn.microsoft.com/en-us/library/dn302338(v=vs.85).aspx) it should work.

 * RSA `modulusLength` must be either one of: _1024_, _2048_, _4096_ bits.

 * RSA `publicExponent` must be either one of: _3_, _65537_.

 * *AES-GCM* `iv` length must be exactly _96_ bits (_12_ octets).

 * Seems `keyUsage` is completely ignored.

Other browsers support
----------------------

https://diafygi.github.io/webcrypto-examples/
