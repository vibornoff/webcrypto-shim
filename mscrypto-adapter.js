/**
 * @file Web Cryptography API adapter
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */

'use strict';

self.crypto || !function () {
    var IE = !!self.msCrypto;

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
        var r = { 'name': (a.name || a || '').toUpperCase() };
        switch ( r.name ) {
            case 'SHA-1':
            case 'SHA-256':
            case 'SHA-384':
                break;
            case 'AES-CBC':
            case 'AES-GCM':
            case 'AES-KW':
                r['length'] = a.length;
                break;
            case 'HMAC':
                r['hash'] = alg(a.hash);
                if ( a.length ) r['length'] = a.length;
                break;
            case 'RSASSA-PKCS1-V1_5':
            case 'RSAES-PKCS1-V1_5':
            case 'RSA-OAEP':
                r['hash'] = alg(a.hash);
                if ( a.publicExponent ) r['publicExponent'] = new Uint8Array(a.publicExponent);
                if ( a.modulusLength ) r['modulusLength'] = a.modulusLength;
                break;
            default:
                throw new SyntaxError("Bad algorithm name");
        }
        return r;
    };

    function b2jwk ( k ) {
        if ( k instanceof ArrayBuffer || k instanceof Uint8Array ) k = JSON.parse( decodeURIComponent( escape( b2s(k) ) ) );
        var jwk = { 'kty': k.kty, 'alg': k.alg, 'ext': k.ext || k.extractable };
        switch ( jwk.kty.toUpperCase() ) {
            case 'OCT':
                jwk.k = k.k;
            case 'RSA':
                [ 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth' ].forEach( function ( x ) { if ( x in k ) jwk[x] = k[x] } );
                break;
            default:
                throw new TypeError("Unsupported key type");
        }
        return jwk;
    }

    function jwk2b ( k ) {
        var jwk = b2jwk(k);
        if ( IE ) jwk['extractable'] = jwk.ext, delete jwk.ext;
        return s2b( unescape( encodeURIComponent( JSON.stringify(jwk) ) ) ).buffer;
    }

    function fixKey ( k, a, u ) {
        k.__defineGetter__( 'algorithm', function () { return a } );
        k.__defineGetter__( 'usages', function () { return u } );
        return k;
    }

    [ 'generateKey', 'importKey', 'exportKey' ]
        .forEach( function ( m ) {
            var _fn = _subtle[m];

            _subtle[m] = function ( a, b, c ) {
                var args = [].slice.call(arguments),
                    ka, ku;

                switch ( m ) {
                    case 'generateKey':
                        ka = alg(a);
                        ku = c;
                        break;
                    case 'importKey':
                    //case 'deriveKey':
                        ka = alg(c);
                        ku = args[4];
                        if ( a === 'jwk' ) args[1] = jwk2b(b);
                        break;
                }

                if ( m === 'generateKey' && ka.name === 'HMAC' && ka.length ) {
                    return _subtle.importKey( 'raw', _crypto.getRandomValues( new Uint8Array( (ka.length+7)>>3 ) ), a, b, c );
                }

                return new Promise(
                    function ( res, rej ) {
                        try {
                            var op = _fn.apply( _subtle, args );

                            op.onabort =
                            op.onerror = function ( e ) {
                                rej(e);
                            };

                            op.oncomplete = function ( r ) {
                                var r = r.target.result;

                                if ( m === 'exportKey' && a === 'jwk' ) {
                                    r = b2jwk(r);
                                }

                                if ( IE ) {
                                    if ( r.publicKey && r.privateKey ) {
                                        fixKey( r.publicKey, ka, ku );
                                        fixKey( r.privateKey, ka, ku );
                                    }
                                    else {
                                        fixKey( r, ka, ku );
                                    }
                                }

                                res(r);
                            };
                        }
                        catch ( e ) {
                            rej(e);
                        }
                    });
            }
        });

    [ 'digest', 'encrypt', 'decrypt', 'sign', 'verify' ]
        .forEach( function ( m ) {
            var _fn = _subtle[m];

            _subtle[m] = function ( a, b, c ) {
                var args = [].slice.call(arguments);

                if ( m === 'decrypt' && a.name.toUpperCase() === 'AES-GCM' ) {
                    var tl = a.tagLength >> 3;
                    args[2] = (c.buffer || c).slice( 0, c.byteLength - tl ),
                    a.tag = (c.buffer || c).slice( c.byteLength - tl );
                }

                return new Promise(
                    function ( res, rej ) {
                        try {
                            var op = _fn.apply( _subtle, args );

                            op.onabort =
                            op.onerror = function ( e ) {
                                rej(e);
                            };

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
                        }
                        catch ( e ) {
                            rej(e);
                        }
                    });
            }
        });

    _subtle['wrapKey'] = function ( a, b, c, d ) {
        return _subtle.exportKey( a, b )
            .then( function ( k ) {
                if ( a === 'jwk' ) k = s2b( unescape( encodeURIComponent( JSON.stringify( b2jwk(k) ) ) ) ).buffer
                return  _subtle.encrypt( d, c, k );
            });
    };

    _subtle['unwrapKey'] = function ( a, b, c, d, e, f, g ) {
        return _subtle.decrypt( d, c, b )
            .then( function ( k ) {
                return _subtle.importKey( a, k, e, f, g );
            });
    };

    self.crypto = Object.create( _crypto, { subtle: { value: _subtle } } );
}();
