var ev = require('equihashverify');
var util = require('./util.js');

var diff1 = global.diff1 = 0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

var algos = module.exports = global.algos = {
    sha256: {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '00000000ffff0000000000000000000000000000000000000000000000000000',
        hash: function(){
            return function(){
                return util.sha256d.apply(this, arguments);
            }
        }
    },
    verushash: {
        multiplier: 1,
        diff: parseInt('0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        hashReserved: '0000000000000000000000000000000000000000000000000000000000000000',
        hash: function(coinOptions) {
            return function(){
                return true;
            }            
        }
    },
    'scrypt': {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nValue = coinConfig.nValue || 1024;
            var rValue = coinConfig.rValue || 1;
            return function(data){
                return multiHashing.scrypt(data,nValue,rValue);
            }
        }
    },
    'equihash': {
        multiplier: 1,
        diff: parseInt('0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        hash: function(coinOptions) {
            let parameters = coinOptions.parameters
            if (!parameters) {
                parameters = {
                    N: 200,
                    K: 9,
                    personalization: 'ZcashPoW'
                }
            }

            let N = parameters.N || 200
            let K = parameters.K || 9
            let personalization = parameters.personalization || 'ZcashPoW'

            return function() {
                return ev.verify.apply(
                    this,
                    [
                        arguments[0],
                        arguments[1],
                        personalization,
                        N,
                        K
                    ]
                )
            }
        }
    },
    'equihash_95_6_scrypt': {
        multiplier: 1,
        diff: parseInt('0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        hash: function(coinOptions) {
            console.log(`Calling the hash function`)
            let parameters = coinOptions.parameters
            if (!parameters) {
                parameters = {
                    N: 95,
                    K: 6,
                    personalization: 'ZcashPoW'
                }
            }

            let N = parameters.N || 95
            let K = parameters.K || 6
            let personalization = parameters.personalization || 'ZcashPoW'

            return function(data) {
                
                console.log(`Calling the hash function result -> another function`)

                var nValue = coinConfig.nValue || 1024;
                var rValue = coinConfig.rValue || 1;
                const eq96_5 = ev.verify.apply(
                    this,
                    [
                        arguments[0],
                        arguments[1],
                        personalization,
                        N,
                        K
                    ]
                );
                return multiHashing.scrypt(eq96_5,nValue,rValue);
                
            }
        }
    },
};

for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;
}
