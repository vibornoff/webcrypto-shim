describe( "ISSUES", function () {
    it( "22", function ( done ) {
        var jwkKey = { "kty": "RSA", "e": "AQAB", "n": "wji8Hk1TfEP_SHGnRcMh9LUslx4pQGMpLssQSIvMXJrJfsz7OZNqPSOgjhefwldiEgNHeDnk87kYQ6LYHLfqVMKyBxn2rUNMcflVKUSQnFtOZZIWnkeji-3OprIXhH7G65zUvYG_rj2x13JtNrDYSQ2A3eJOIWvrA5TBFOSDh9M", "alg": "RSA-OAEP", "ext": true },
            jwkAlg = { name: "RSA-OAEP", hash: { name: "SHA-1" } },
            jwkExt = true,
            jwkUse = ["encrypt"];

        crypto.subtle.importKey( "jwk", jwkKey, jwkAlg, jwkExt, jwkUse )
            .then( function ( pubKey ) {
                expect(pubKey).toEqual(jasmine.any(CryptoKey));
            })
            .catch(fail)
            .then(done);
    });
});
