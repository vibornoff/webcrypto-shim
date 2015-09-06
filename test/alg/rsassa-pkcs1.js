describe( 'RSASSA-PKCS1-v1.5_SHA-256', function () {
    var alg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: x2b('10001') };
    var keyPair;

    var genKeyPairComplete = crypto.subtle.generateKey( alg, false, [ 'sign', 'verify' ] )
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

    it( 'importKey / jwk / public', function ( done ) {
        var jwkKey = {
            "kty":"RSA",
            "alg":"RS256",
            "n":"zjqltECmgT1Mo925UoACQssXARROi2PjGktxw6NgPVyG3LiSxY4dxGiP5fDjJykkPx8LKIk6k-71Ut5RlcKJQdwyluB7XjNWkx8om7NZ8337fsS8Yp_DBgXMfVI99t34SI0HzHZ_vA2Ang1eKdUQPK7Kq8mD6swS9UQJFzQfecD7Xb46dw4jtJ2lHC4NLqwmHSu8Xf3Q6efOEf53y24_qTptjA-D-gyn51iFuoEssoNdpWxPMP2ExpXz9-Ly2VwHzabNFjAc-cZuK4Tyc_1l3OPbQ82fDi-iSJodzNbpRCbm-d47ai0gROui4iunL2pwM6vooJZA72oxceZGrFGU-w",
            "e":"AQAB",
        };

        crypto.subtle.importKey( 'jwk', jwkKey, alg, true, [ 'verify' ] )
            .then( function ( res ) {
                expect(res).toBeDefined();
                expect(res instanceof CryptoKey).toBe(true);
                expect(res.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });

    it( 'importKey / jwk / private', function ( done ) {
        var jwkKey = {
            "kty":"RSA",
            "alg":"RS256",
            "n":"zjqltECmgT1Mo925UoACQssXARROi2PjGktxw6NgPVyG3LiSxY4dxGiP5fDjJykkPx8LKIk6k-71Ut5RlcKJQdwyluB7XjNWkx8om7NZ8337fsS8Yp_DBgXMfVI99t34SI0HzHZ_vA2Ang1eKdUQPK7Kq8mD6swS9UQJFzQfecD7Xb46dw4jtJ2lHC4NLqwmHSu8Xf3Q6efOEf53y24_qTptjA-D-gyn51iFuoEssoNdpWxPMP2ExpXz9-Ly2VwHzabNFjAc-cZuK4Tyc_1l3OPbQ82fDi-iSJodzNbpRCbm-d47ai0gROui4iunL2pwM6vooJZA72oxceZGrFGU-w",
            "e":"AQAB",
            "d":"awviK1hLlVYeTAixQ3OSuNz2SecihhQJNALpQGWzdOZsUnG0LbuBFAw6dV6-aftfByyz_AyPTW6CBMvFiXj7CiakU9Cd-N2pGKDZ0Ugdbth8DOdN6duHvb6Q0JQ5-cRqNi6OV8FCuHhBxMinkgs4bGdGaDknsl7PkGQKW_MAS4_Cq1e9vGhRDYBhIzw-umzW54YgVAOHhnFLR9WHohZhWzNAlFHAnSz7lV1N4ixt_VJl24GpcbK9d1dSzHi8Jn5cPu7D8SHHlS0KLofqfIfrMshJ3jX_OHnsYTHFdGF3WO36kC1zQxhDQoXR5ege8Dou5x3Yxx_YBWFJ_7HF2v1t0Q",
            "dp":"FkWoVRH88LGHksR_wFdzirwDzQVCirMiL3AcsfHGZzonYjsI2myK92Ogc1BGwrzB-oZM4WfUdOVJvRSeicI2YuBZFFhFMhVu_7enf_q2lG1HseZ4VhoSishTIt8rwiOUh1pescfN3blKK7abwzeOHol7L-uh7jWPWbiAANwHQEE",
            "dq":"a7GkVy4ZK6G1iTJvXfGwalXr2wzqGGOaWgMYt25E7hqWWbqsuh35qcONYKCEiXTV2ay3V1D69lc2o5-vxTfMgu2IL36LXGrrKfueFdTPysXOTD_w6qg0e7y7HB6d0MzWHdiOsedwDXSQWDhGR0OulEtLFWrQ-0Ph_3q1oc4cNfk",
            "p":"_h3jPckueHHAA2Px9DLNd8eZt6sfX86oZ4AvJ91uN6VgGzSMuO5ptn0j9sMfgqcS3W1u32hfaIu0hI_Za7XYSyy-ms0VJCDZuPzBlo-fsbtezgB0y1arW8KU0ncGeejD39yda_dtWXSV-Odf_gIy5qrcw7Dt5fMOOtLLpfk7BV0",
            "q":"z8HoIiPAaZSkLYPROMQnozV9P9FB9if9VFl7wP6dvQURPm7Kxjy8RJVRv2tBdEUU0TVE91n-ENX9ILEkihwLp9GLNKY6IxKnsHmYYZAX3qTymiKkehXggCzIdC6dZksbXAPVCQ8OS1SnU6ZnvzVdtndrdphEh46kyLlau5McRjc",
            "qi":"QE5ThOvSdfboEDJ4q64BVn8SPanj3uG2xl5Qh_aJZBAqQgwm2rQ6koyFPCsLIi_pyk5e_l1hslEdpVTDxE7wTs39ZfiLbX73W_4JEbCzr8fjEUKO6-mkpcjTUY_SHVvGIz9tUAPy8N-62YznLMzO_DQdSphHUchPZnXF69a8TvE",
        };

        crypto.subtle.importKey( 'jwk', jwkKey, alg, true, [ 'sign' ] )
            .then( function ( res ) {
                expect(res).toBeDefined();
                expect(res instanceof CryptoKey).toBe(true);
                expect(res.algorithm).toEqual( normalizeAlg(alg) );
            })
            .catch(fail)
            .then(done);
    });
});
