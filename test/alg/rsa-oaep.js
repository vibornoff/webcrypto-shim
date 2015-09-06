describe( 'RSA-OAEP_SHA-1', function () {
    var alg = { name: 'RSA-OAEP', hash: 'SHA-1', modulusLength: 2048, publicExponent: x2b('10001') };
    var keyPair;

    var genKeyPairComplete = crypto.subtle.generateKey( alg, false, [ 'encrypt', 'decrypt' ] )
            .then( function ( res ) {
                keyPair = res;
            });

    it( "generateKey", function ( done ) {
        genKeyPairComplete
            .then( function () {
                expect(keyPair).toBeDefined();

                expect(keyPair.publicKey).toBeDefined();
                expect(keyPair.publicKey.type).toBe('public');
                expect(keyPair.publicKey.extractable).toBe(true);
                expect(keyPair.publicKey.algorithm).toEqual( normalizeAlg(alg) );

                expect(keyPair.privateKey).toBeDefined();
                expect(keyPair.privateKey.type).toBe('private');
                expect(keyPair.privateKey.extractable).toBe(false);
                expect(keyPair.privateKey.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    it( 'encrypt and then decrypt', function ( done ) {
        genKeyPairComplete
            .then ( function () {
                return crypto.subtle.encrypt( alg, keyPair.publicKey, s2b('test') );
            })
            .then( function ( res ) {
                expect(res).toBeDefined();
                expect(res).toEqual(jasmine.any(ArrayBuffer));
                expect(res.byteLength).toBe(256);
                return res;
            })
            .then ( function ( res ) {
                return crypto.subtle.decrypt( alg, keyPair.privateKey, res );
            })
            .then( function ( res ) {
                expect(res).toEqual(jasmine.any(ArrayBuffer));
                expect(res.byteLength).toBe(4);
                expect( b2s(res) ).toBe('test');
                return res;
            })
            .catch(fail)
            .then(done);
    });

    it( 'importKey / jwk', function ( done ) {
        var jwkKey = {
            "kty":"RSA",
            "alg":"RSA-OAEP",
            "n":"zjqltECmgT1Mo925UoACQssXARROi2PjGktxw6NgPVyG3LiSxY4dxGiP5fDjJykkPx8LKIk6k-71Ut5RlcKJQdwyluB7XjNWkx8om7NZ8337fsS8Yp_DBgXMfVI99t34SI0HzHZ_vA2Ang1eKdUQPK7Kq8mD6swS9UQJFzQfecD7Xb46dw4jtJ2lHC4NLqwmHSu8Xf3Q6efOEf53y24_qTptjA-D-gyn51iFuoEssoNdpWxPMP2ExpXz9-Ly2VwHzabNFjAc-cZuK4Tyc_1l3OPbQ82fDi-iSJodzNbpRCbm-d47ai0gROui4iunL2pwM6vooJZA72oxceZGrFGU-w",
            "e":"AQAB",
            "d":"awviK1hLlVYeTAixQ3OSuNz2SecihhQJNALpQGWzdOZsUnG0LbuBFAw6dV6-aftfByyz_AyPTW6CBMvFiXj7CiakU9Cd-N2pGKDZ0Ugdbth8DOdN6duHvb6Q0JQ5-cRqNi6OV8FCuHhBxMinkgs4bGdGaDknsl7PkGQKW_MAS4_Cq1e9vGhRDYBhIzw-umzW54YgVAOHhnFLR9WHohZhWzNAlFHAnSz7lV1N4ixt_VJl24GpcbK9d1dSzHi8Jn5cPu7D8SHHlS0KLofqfIfrMshJ3jX_OHnsYTHFdGF3WO36kC1zQxhDQoXR5ege8Dou5x3Yxx_YBWFJ_7HF2v1t0Q",
            "dp":"FkWoVRH88LGHksR_wFdzirwDzQVCirMiL3AcsfHGZzonYjsI2myK92Ogc1BGwrzB-oZM4WfUdOVJvRSeicI2YuBZFFhFMhVu_7enf_q2lG1HseZ4VhoSishTIt8rwiOUh1pescfN3blKK7abwzeOHol7L-uh7jWPWbiAANwHQEE",
            "dq":"a7GkVy4ZK6G1iTJvXfGwalXr2wzqGGOaWgMYt25E7hqWWbqsuh35qcONYKCEiXTV2ay3V1D69lc2o5-vxTfMgu2IL36LXGrrKfueFdTPysXOTD_w6qg0e7y7HB6d0MzWHdiOsedwDXSQWDhGR0OulEtLFWrQ-0Ph_3q1oc4cNfk",
            "p":"_h3jPckueHHAA2Px9DLNd8eZt6sfX86oZ4AvJ91uN6VgGzSMuO5ptn0j9sMfgqcS3W1u32hfaIu0hI_Za7XYSyy-ms0VJCDZuPzBlo-fsbtezgB0y1arW8KU0ncGeejD39yda_dtWXSV-Odf_gIy5qrcw7Dt5fMOOtLLpfk7BV0",
            "q":"z8HoIiPAaZSkLYPROMQnozV9P9FB9if9VFl7wP6dvQURPm7Kxjy8RJVRv2tBdEUU0TVE91n-ENX9ILEkihwLp9GLNKY6IxKnsHmYYZAX3qTymiKkehXggCzIdC6dZksbXAPVCQ8OS1SnU6ZnvzVdtndrdphEh46kyLlau5McRjc",
            "qi":"QE5ThOvSdfboEDJ4q64BVn8SPanj3uG2xl5Qh_aJZBAqQgwm2rQ6koyFPCsLIi_pyk5e_l1hslEdpVTDxE7wTs39ZfiLbX73W_4JEbCzr8fjEUKO6-mkpcjTUY_SHVvGIz9tUAPy8N-62YznLMzO_DQdSphHUchPZnXF69a8TvE",
        };

        crypto.subtle.importKey( 'jwk', jwkKey, alg, true, [ 'decrypt' ] )
            .then( function ( res ) {
                expect(res).toBeDefined();
                expect(res instanceof CryptoKey).toBe(true);
                expect(res.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });
});

describe( 'RSA-OAEP_SHA-256', function () {
    var alg = { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 2048, publicExponent: x2b('10001') },
        spkiPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm6Lnc6cNKMWdXDbGKoT9VZCGAP+IFCKMWmQHROvTGPBrQm7NwSaC8CKhsNG12sauM/xv7qzc/OuZ0Qb9hfUBRrchGfSled+iewfD1MWMhNZgOpZHWBEY75xFbW4O3rKGOeimZr4I//WMpVFu2Gbw1POcIPT8g9XNOon+Q1fWR0nXnyupVOJqGTs6+TluAm9sRpXfjN4vDZp9u9tF4lvyEv8PEeJtaKeoAyXh2mEZlHHVSCn238TWe2JZhlhUbSYcZKmISWKQHi+Zf78gPJLa+oSljJKrnPncrX4JLz8QKjnBCa01Mikww6aJbMzFxy6UF4pcnuvnuaa8Qs/U5Q3/vwIDAQAB",
        pkcsPrvKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCboudzpw0oxZ1cNsYqhP1VkIYA/4gUIoxaZAdE69MY8GtCbs3BJoLwIqGw0bXaxq4z/G/urNz865nRBv2F9QFGtyEZ9KV536J7B8PUxYyE1mA6lkdYERjvnEVtbg7esoY56KZmvgj/9YylUW7YZvDU85wg9PyD1c06if5DV9ZHSdefK6lU4moZOzr5OW4Cb2xGld+M3i8Nmn2720XiW/IS/w8R4m1op6gDJeHaYRmUcdVIKfbfxNZ7YlmGWFRtJhxkqYhJYpAeL5l/vyA8ktr6hKWMkquc+dytfgkvPxAqOcEJrTUyKTDDpolszMXHLpQXilye6+e5prxCz9TlDf+/AgMBAAECggEBAIytdRQevVBLP2+ouvqX9v0ug1HHp9K7X64cmE198/Oo7OrBiQ27p8MzKn/PLtevmqq21N4iNiYPN5uu+93nld27jhoN/rzonc8jN6nNXrR7qcOLLrW1zppW4JKHVr2JFLanSjG4OB5Ub2rG7rCAa9Ow10Ea8FyiFr2BGej5LmCEP2/Nr1Olf1EdOz9HlZOF+bMewpWL/c4qxGLWMBaSrhflK65EZQCZdHKgnZ831M2UOTsrbRkdg2b+YMhthfGRl6730D93glvfITINWZLuwxnA6kYQMqRdbuOqAo5FKyrS32oZkq3cX+EXxt6iloii5U7L4t3eaNoj/KtpXKSYEeECgYEAzhR8lN9OSJdvTl9PcQMDxpTrlsjCbxCiA74BscfTFn5hwJujC8zEN7+FGKJu6uclCAfGRXrs2t4OFWZ543ugnVZszTS33LaSUw5/aNJ2PTOgv+QJj4U6GpJwNQ+YA+7u2EKeh5xxYyQZup15yAekc84UnOB6PJMSb1RcGonJw/cCgYEAwVZI2mOhyp2DO/OKFKqZWvYFfwR4mNEjk8jJlbU+JwyyPe4Z5AMB3coIRwUDvINF1y9ggKLHCkebm3Nt2I1eAlvzE+IP/6peAv7CkOQXJSSXCuN6wCCz9q+BCBN79t/iDNdNVlFhjgnK4fyz6ySY3xod1TSvTKUIasUhF036oHkCgYEAuQPfjXCmQbnjbkNXeSixvRl6IVeAaGJQcnel4cx7ERjJ/jg8u51NFJfXkHRUjISU1I7WTQ69kwoFLuVfzQHzAw7Sg7Eu2PL4j6TWcm9xRCUTzvOWOcnsjmqmXpzvZ6idun6lAS9NBSsmBkrXSOTDmkyMaQOH+tY3mMfuIM1P3aUCgYBDu6bqW91izqwbZMcLVnlDlM14ImjdoOeF7uIwwL51j80iRThs2WDeAtnDh843TQY6zS5R4rU4tL2fSGFDbMNysCQI4zoXp+gnxHkFqeMx8A+6kNeAV/S0h+f8nFbhtq3LMeK2SuyShnu9kHq39qpX/x5Ug5CmmWrJfSaKs5cKgQKBgGzXgoAjBKkYj44o4RHa1NJRkSHAOGzbzsA63BE1hTu+Tf2GoFK3BrZmxaXHVyMn/gAY8ZK6b8hEO84v0Oh8Cp5rlnnjs/KksaaDdE6JhvPh1xirK7zsi8ZLM6au8VGeSJfdupwmECdT4lwMgkM3N6sVSs0iaBQ9mKmrxBcdd1He",
        jwkPubKey = {"alg":"RSA-OAEP-256","e":"AQAB","ext":true,"key_ops":["encrypt"],"kty":"RSA","n":"m6Lnc6cNKMWdXDbGKoT9VZCGAP-IFCKMWmQHROvTGPBrQm7NwSaC8CKhsNG12sauM_xv7qzc_OuZ0Qb9hfUBRrchGfSled-iewfD1MWMhNZgOpZHWBEY75xFbW4O3rKGOeimZr4I__WMpVFu2Gbw1POcIPT8g9XNOon-Q1fWR0nXnyupVOJqGTs6-TluAm9sRpXfjN4vDZp9u9tF4lvyEv8PEeJtaKeoAyXh2mEZlHHVSCn238TWe2JZhlhUbSYcZKmISWKQHi-Zf78gPJLa-oSljJKrnPncrX4JLz8QKjnBCa01Mikww6aJbMzFxy6UF4pcnuvnuaa8Qs_U5Q3_vw"},
        jwkPrvKey = {"alg":"RSA-OAEP-256","d":"jK11FB69UEs_b6i6-pf2_S6DUcen0rtfrhyYTX3z86js6sGJDbunwzMqf88u16-aqrbU3iI2Jg83m6773eeV3buOGg3-vOidzyM3qc1etHupw4sutbXOmlbgkodWvYkUtqdKMbg4HlRvasbusIBr07DXQRrwXKIWvYEZ6PkuYIQ_b82vU6V_UR07P0eVk4X5sx7ClYv9zirEYtYwFpKuF-UrrkRlAJl0cqCdnzfUzZQ5OyttGR2DZv5gyG2F8ZGXrvfQP3eCW98hMg1Zku7DGcDqRhAypF1u46oCjkUrKtLfahmSrdxf4RfG3qKWiKLlTsvi3d5o2iP8q2lcpJgR4Q","dp":"uQPfjXCmQbnjbkNXeSixvRl6IVeAaGJQcnel4cx7ERjJ_jg8u51NFJfXkHRUjISU1I7WTQ69kwoFLuVfzQHzAw7Sg7Eu2PL4j6TWcm9xRCUTzvOWOcnsjmqmXpzvZ6idun6lAS9NBSsmBkrXSOTDmkyMaQOH-tY3mMfuIM1P3aU","dq":"Q7um6lvdYs6sG2THC1Z5Q5TNeCJo3aDnhe7iMMC-dY_NIkU4bNlg3gLZw4fON00GOs0uUeK1OLS9n0hhQ2zDcrAkCOM6F6foJ8R5BanjMfAPupDXgFf0tIfn_JxW4batyzHitkrskoZ7vZB6t_aqV_8eVIOQpplqyX0mirOXCoE","e":"AQAB","ext":true,"key_ops":["decrypt"],"kty":"RSA","n":"m6Lnc6cNKMWdXDbGKoT9VZCGAP-IFCKMWmQHROvTGPBrQm7NwSaC8CKhsNG12sauM_xv7qzc_OuZ0Qb9hfUBRrchGfSled-iewfD1MWMhNZgOpZHWBEY75xFbW4O3rKGOeimZr4I__WMpVFu2Gbw1POcIPT8g9XNOon-Q1fWR0nXnyupVOJqGTs6-TluAm9sRpXfjN4vDZp9u9tF4lvyEv8PEeJtaKeoAyXh2mEZlHHVSCn238TWe2JZhlhUbSYcZKmISWKQHi-Zf78gPJLa-oSljJKrnPncrX4JLz8QKjnBCa01Mikww6aJbMzFxy6UF4pcnuvnuaa8Qs_U5Q3_vw","p":"zhR8lN9OSJdvTl9PcQMDxpTrlsjCbxCiA74BscfTFn5hwJujC8zEN7-FGKJu6uclCAfGRXrs2t4OFWZ543ugnVZszTS33LaSUw5_aNJ2PTOgv-QJj4U6GpJwNQ-YA-7u2EKeh5xxYyQZup15yAekc84UnOB6PJMSb1RcGonJw_c","q":"wVZI2mOhyp2DO_OKFKqZWvYFfwR4mNEjk8jJlbU-JwyyPe4Z5AMB3coIRwUDvINF1y9ggKLHCkebm3Nt2I1eAlvzE-IP_6peAv7CkOQXJSSXCuN6wCCz9q-BCBN79t_iDNdNVlFhjgnK4fyz6ySY3xod1TSvTKUIasUhF036oHk","qi":"bNeCgCMEqRiPjijhEdrU0lGRIcA4bNvOwDrcETWFO75N_YagUrcGtmbFpcdXIyf-ABjxkrpvyEQ7zi_Q6HwKnmuWeeOz8qSxpoN0TomG8-HXGKsrvOyLxkszpq7xUZ5Il926nCYQJ1PiXAyCQzc3qxVKzSJoFD2YqavEFx13Ud4"},
        encMsg1 = "lJ5oWi3eq9T0JErf3zGGjo3EaABJb/xTuL10cmLGShEVL418x4BRRP7/qmt07KSShm/ZryblVSpfPR1oUOagNhaLN+FT24gIdWBIgHoNF6+/o6y2blnGJypi4DgyoacmFCpZtA08Yhkfepig4681QpdSV5vSLqyjRHapTFQvQgZ8sLD+Mkh5E+umfTy1BDktXQfuzg5s+qcZ+sCl7UGRSR8/7HERLxjsZADmALKLVZ5S1cnCVC4FUagX5OnqAX1AcfGdR93aaB6GKDITfVzzkTuo0I1qk0u7a8LCgLiBTzV6lFARStFQPtj9DokP15w3r62UlM4dQweQxXMU6mkCpw==",
        encMsg2 = "dUu67hKWD0m8rPzp1EJeY6VtcJZN+ATC1QHWTjyQWTUsmb5AQxs55FkFNIHWphXTgrjg6V4jFp2fgWdgNvQiJOiUdMURJq/vcR2M1lIbcZcUbPBoVjiQf6dTr1B2ttuel8QorNn58PKEzlYfr/EqA7jkg3J2KuMGBxyGKw8pfCDVqGNTNZcj67nh44wHvz7vTRGcWzys1UcqtfdMMvwX2i4RSZU5IvnvikpLBFdF77nVooemwo1W8/nmZg/uFCO/b307xTKwuiTvRNixUTPHevgl7mlI6rv1jeOOUKEHiC3VNaPc6jQ0VrjqpitfwNpg206WZzGB1cowE8VVM9jkOQ==";

    var importPkcsPrvKeyComplete = crypto.subtle.importKey( 'pkcs8', s2b( atob(pkcsPrvKey) ), alg, false, [ 'decrypt' ] );

    var importJwkPrvKeyComplete = crypto.subtle.importKey( 'jwk', jwkPrvKey, alg, false, [ 'decrypt' ] );

    it( 'importKey / spki', function ( done ) {
        crypto.subtle.importKey( 'spki', s2b( atob(spkiPubKey) ), alg, true, [ 'encrypt' ] )
            .then( function ( pubKey ) {
                expect(pubKey).toBeDefined();
                expect(pubKey instanceof CryptoKey).toBe(true);
                expect(pubKey.type).toBe('public');
                expect(pubKey.extractable).toBe(true);
                expect(pubKey.usages).toEqual(['encrypt']);
                expect(pubKey.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    it( 'importKey / pkcs8', function ( done ) {
        importPkcsPrvKeyComplete
            .then( function ( prvKey ) {
                expect(prvKey).toBeDefined();
                expect(prvKey instanceof CryptoKey).toBe(true);
                expect(prvKey.type).toBe('private');
                expect(prvKey.extractable).toBe(false);
                expect(prvKey.usages).toEqual(['decrypt']);
                expect(prvKey.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    it( 'importKey / jwk-pub', function ( done ) {
        crypto.subtle.importKey( 'jwk', jwkPubKey, alg, true, [ 'encrypt' ] )
            .then( function ( pubKey ) {
                expect(pubKey).toBeDefined();
                expect(pubKey instanceof CryptoKey).toBe(true);
                expect(pubKey.type).toBe('public');
                expect(pubKey.extractable).toBe(true);
                expect(pubKey.usages).toEqual(['encrypt']);
                expect(pubKey.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    it( 'importKey / jwk-prv', function ( done ) {
        importJwkPrvKeyComplete
            .then( function ( prvKey ) {
                expect(prvKey).toBeDefined();
                expect(prvKey instanceof CryptoKey).toBe(true);
                expect(prvKey.type).toBe('private');
                expect(prvKey.extractable).toBe(false);
                expect(prvKey.usages).toEqual(['decrypt']);
                expect(prvKey.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    xit( 'decrypt / ""', function ( done ) {
        importPkcsPrvKeyComplete
            .catch ( function ( ) {
                return importJwkPrvKeyComplete;
            })
            .then( function ( prvKey ) {
                return crypto.subtle.decrypt( alg, prvKey, s2b( atob(encMsg1) ) )
            })
            .then( function ( msg1 ) {
                expect(msg1).toEqual(jasmine.any(ArrayBuffer));
                expect(b2s(msg1)).toBe("");
            })
            .catch(fail)
            .then(done);
    });

    it( 'decrypt / "Hello World!"', function ( done ) {
        importPkcsPrvKeyComplete
            .catch ( function ( ) {
                return importJwkPrvKeyComplete;
            })
            .then( function ( prvKey ) {
                return crypto.subtle.decrypt( alg, prvKey, s2b( atob(encMsg2) ) );
            })
            .then( function ( msg2 ) {
                expect(msg2).toEqual(jasmine.any(ArrayBuffer));
                expect(b2s(msg2)).toBe("Hello World!");
            })
            .catch(fail)
            .then(done);
    });
});

