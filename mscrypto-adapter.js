/**
 * @file Web Cryptography API adapter
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */

'use strict';

self.crypto || !function () {
    var _crypto = self.msCrypto || self.webkitCrypto;
    if ( !_crypto ) return;

    self.crypto = {
        getRandomValues: function () {
            return _crypto.getRandomValues.apply( _crypto, arguments );
        }
    };
}();

!self.crypto || self.crypto.subtle || !function () {
    var _subtle = self.crypto.webkitSubtle || ( self.msCrypto && self.msCrypto.subtle );
    if ( !_subtle ) return;

    self.crypto.subtle = _subtle;

    if ( self.msCrypto ) {
        if ( typeof Promise !== 'function' )
            throw "Promise support required";

        if ( typeof CryptoKey === 'undefined' )
            self.CryptoKey = Key;

        CryptoKey.prototype.__defineGetter__( 'usages', function () {
            return this.keyUsage || [];
        });

        [ 'decrypt', 'deriveBits', 'deriveKey', 'digest', 'encrypt', 'exportKey', 'generateKey' ,'importKey', 'sign', 'unwrapKey', 'verify', 'wrapKey' ]
            .forEach( function ( m ) {
                var fn = _subtle[m];
                _subtle[m] = function ( alg ) {
                    try {
                        if ( m === 'decrypt' && alg.name.toUpperCase() === 'AES-GCM' ) {
                            var tl = alg.tagLength >> 3, buff = arguments[2];
                            arguments[2] = buff.slice( 0, buff.byteLength - tl ),
                            alg.tag = buff.slice( buff.byteLength - tl );
                        }

                        var op = fn.apply( this, arguments );
                        return new Promise( function ( res, rej ) {
                            op.onabort    =
                            op.onerror    = function ( e ) { rej(e) };
                            op.oncomplete = function ( r ) {
                                var r = r.target.result;

                                if ( m === 'encrypt' && r instanceof AesGcmEncryptResult ) {
                                    var c = r.ciphertext, t = r.tag;
                                    r = new Uint8Array( c.byteLength + t.byteLength );
                                    r.set( new Uint8Array(c), 0 );
                                    r.set( new Uint8Array(t), c.byteLength );
                                    r = r.buffer;
                                }

                                res(r);
                            };
                        });
                    }
                    catch ( ex ) {
                        return Promise.reject(ex);
                    }
                }
            });
    }
}();
