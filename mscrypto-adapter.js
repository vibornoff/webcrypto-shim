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

        function s2b ( s ) {
            var b = new Uint8Array(s.length);
            for ( var i = 0; i < s.length; i++ ) b[i] = s.charCodeAt(i);
            return b;
        }

        function b2s ( b ) {
            if ( b instanceof ArrayBuffer ) b = new Uint8Array(b);
            return String.fromCharCode.apply( String, b );
        }

        [ 'decrypt', 'deriveBits', 'deriveKey', 'digest', 'encrypt', 'exportKey', 'generateKey' ,'importKey', 'sign', 'unwrapKey', 'verify', 'wrapKey' ]
            .forEach( function ( m ) {
                var fn = _subtle[m];
                _subtle[m] = function ( a, b, c ) {
                    try {
                        if ( m === 'decrypt' && a.name.toUpperCase() === 'AES-GCM' ) {
                            var tl = a.tagLength >> 3;
                            arguments[2] = c.slice( 0, c.byteLength - tl ),
                            a.tag = c.slice( c.byteLength - tl );
                        }

                        if ( m === 'importKey' && a === 'jwk' ) {
                            if ( b instanceof ArrayBuffer ) b = new Uint8Array(b);
                            if ( b instanceof Uint8Array ) b = JSON.parse( decodeURIComponent( escape( b2s(b) ) ) );

                            var jwk = { kty: b.kty, alg: b.alg, extractable: b.ext };
                            switch ( jwk.kty ) {
                                case 'oct':
                                    jwk.k = b.k;
                                case 'RSA':
                                    [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ].forEach( function ( x ) { if ( x in b ) jwk[x] = b[x] } );
                                    break;
                            }

                            arguments[1] = s2b( unescape( encodeURIComponent( JSON.stringify(jwk) ) ) ).buffer;
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

                                if ( m === 'exportKey' && a === 'jwk' ) {
                                    r = JSON.parse( decodeURIComponent( escape( b2s(r) ) ) );

                                    var jwk = { kty: r.kty, alg: r.alg, ext: r.extractable };
                                    switch ( jwk.kty ) {
                                        case 'oct':
                                            jwk.k = r.k;
                                            break;
                                        case 'RSA':
                                            [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi' ].forEach( function ( x ) { if ( x in r ) jwk[x] = r[x] } );
                                            break;
                                    }

                                    r = jwk;
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
