mscrypto-adapter.js
===================

Web Cryptography API adapter for *Internet Explorer 11*

Bugs of `window.msCrypto.subtle`
-------------------------------

 * Doc [claims](https://msdn.microsoft.com/en-us/library/dn302338(v=vs.85).aspx) `SHA-1` support for `digest`, but `NotSupportedError` is thrown when trying to use it.

 * Crypto operation on an empty buffer never returns any result.
