/**
 * @file Web Cryptography API adapter
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */

'use strict';

self.crypto || !function () {
    var _crypto = self.msCrypto;
    if ( !_crypto ) return;

    var _subtle = _crypto.subtle;
    if ( !_subtle ) return;

    if ( typeof Promise !== 'function' )
        throw "Promise support required";

    if ( typeof CryptoKey === 'undefined' )
        self.CryptoKey = Key;

    function s2b ( s ) {
        var b = new Uint8Array(s.length);
        for ( var i = 0; i < s.length; i++ ) b[i] = s.charCodeAt(i);
        return b;
    }

    function b2s ( b ) {
        if ( b instanceof ArrayBuffer ) b = new Uint8Array(b);
        return String.fromCharCode.apply( String, b );
    }

    function alg ( a ) {
        var r = { name: (a.name || a || '').toUpperCase() };
        switch ( r.name ) {
            case 'SHA-1':
            case 'SHA-256':
            case 'SHA-384':
                break;
            case 'AES-CBC':
            case 'AES-GCM':
            case 'AES-KW':
                r.length = a.length;
                break;
            case 'HMAC':
                r.hash = alg(a.hash);
                if ( a.length ) r.length = a.length;
                break;
            case 'RSASSA-PKCS1-V1_5':
            case 'RSAES-PKCS1-V1_5':
            case 'RSA-OAEP':
                r.hash = alg(a.hash);
                if ( a.publicExponent ) r.publicExponent = new Uint8Array(a.publicExponent);
                if ( a.modulusLength ) r.modulusLength = a.modulusLength;
                break;
            default:
                throw new SyntaxError("Bad algorithm name");
        }
        return r;
    };

    [ 'digest', 'encrypt', 'decrypt', 'sign', 'verify', 'importKey', 'exportKey', 'generateKey' ]
        .forEach( function ( m ) {
            var fn = _subtle[m];
            _subtle[m] = function ( a, b, c ) {
                try {
                    var keyAlg, keyUse;
                    switch ( m ) {
                        case 'generateKey':
                            keyAlg = alg(a);
                            keyUse = c;
                            break;
                        case 'importKey':
                        //case 'deriveKey':
                            keyAlg = alg(c);
                            keyUse = arguments[4];
                            break;
                        case 'unwrapKey':
                            keyAlg = alg( arguments[4] );
                            keyUse = arguments[6];
                            break;
                    }

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
                                [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth' ].forEach( function ( x ) { if ( x in b ) jwk[x] = b[x] } );
                                break;
                        }
                        arguments[1] = s2b( unescape( encodeURIComponent( JSON.stringify(jwk) ) ) ).buffer;
                    }

                    if ( m === 'generateKey' && keyAlg.name === 'HMAC' && keyAlg.length ) {
                        return this.importKey( 'raw', _crypto.getRandomValues( new Uint8Array( (keyAlg.length+7)>>3 ) ), a, b, c );
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
                                        [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth' ].forEach( function ( x ) { if ( x in r ) jwk[x] = r[x] } );
                                        break;
                                }
                                r = jwk;
                            }

                            if ( keyAlg ) {
                                if ( r.publicKey && r.privateKey ) {
                                    r.publicKey.__defineGetter__( 'algorithm', function () { return keyAlg } );
                                    r.publicKey.__defineGetter__( 'usages', function () { return keyAlg } );
                                    r.privateKey.__defineGetter__( 'algorithm', function () { return keyAlg } );
                                    r.privateKey.__defineGetter__( 'usages', function () { return keyUse } );
                                }
                                else {
                                    r.__defineGetter__( 'algorithm', function () { return keyAlg } );
                                    r.__defineGetter__( 'usages', function () { return keyUse } );
                                }
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

    self.crypto = Object.create( _crypto, { subtle: { value: _subtle } } );
}();
