/**
 * @file Web Cryptography API adapter for Internet Explorer 11
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */

'use strict';

if ( typeof Promise !== 'function' )
    throw "Promise support required";

self.crypto || !function () {
    if ( !self.msCrypto ) return;

    var _subtle = self.msCrypto.subtle;

    function _promise ( op ) {
        return new Promise(
            function ( resolve, reject ) {
                op.onabort    =
                op.onerror    = function ( e ) { reject(e)          };
                op.oncomplete = function (   ) { resolve(op.result) };
            }
        );
    }

    function _adapt ( fn ) {
        return function () {
            try {
                return _promise( fn.apply( _subtle, arguments ) );
            }
            catch ( ex ) {
                return Promise.reject(ex);
            }
        }
    }

    var subtleAdapter = { digest: _digest };
    [ 'decrypt', 'deriveBits', 'deriveKey', 'digest', 'encrypt', 'exportKey', 'generateKey' ,'importKey', 'sign', 'unwrapKey', 'verify', 'wrapKey' ]
        .forEach( function ( method ) { subtleAdapter[method] = _adapt( _subtle[method] ) } );

    self.crypto = {
        getRandomValues: self.msCrypto.getRandomValues,
        subtle:         subtleAdapter,
    };
}();
