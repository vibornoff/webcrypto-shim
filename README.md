mscrypto-adapter.js
===================

Web Cryptography API adapter for *Internet Explorer 11*

Quick start w/ Bower
--------------------

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

Bugs of `window.msCrypto.subtle`
-------------------------------

 * Doc [claims](https://msdn.microsoft.com/en-us/library/dn302338(v=vs.85).aspx) `SHA-1` support for `digest`, but `NotSupportedError` is thrown when trying to use it.

 * Crypto operation on an empty buffer never returns any result.
