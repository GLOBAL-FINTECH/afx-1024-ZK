pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";

// AFX-1024 unified zero-knowledge authorization circuit.
//
// Private inputs:
//   secret       Hidden credential or secret value.
//   salt         Hidden blinding value used to derive the commitment.
//
// Public inputs:
//   messageHash  Field-safe hash of the authorized message.
//   domain       Application, chain, tenant, or protocol domain identifier.
//   nonce        Unique authorization nonce used for replay protection.
//   scope        Public proof scope or policy identifier.
//
// Public outputs:
//   commitment            Poseidon(secret, salt)
//   authorizationTag      Poseidon(secret, messageHash, domain, nonce)
//   authorizationNullifier Poseidon(secret, domain, nonce)
//   scopeNullifier        Poseidon(secret, scope)
//
// A valid proof demonstrates knowledge of secret and salt that bind all
// outputs to the declared public message, domain, nonce, and scope without
// revealing either private value.
template AFX1024() {
    signal input secret;
    signal input salt;
    signal input messageHash;
    signal input domain;
    signal input nonce;
    signal input scope;

    signal output commitment;
    signal output authorizationTag;
    signal output authorizationNullifier;
    signal output scopeNullifier;

    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== salt;
    commitment <== commitmentHasher.out;

    component authorizationHasher = Poseidon(4);
    authorizationHasher.inputs[0] <== secret;
    authorizationHasher.inputs[1] <== messageHash;
    authorizationHasher.inputs[2] <== domain;
    authorizationHasher.inputs[3] <== nonce;
    authorizationTag <== authorizationHasher.out;

    component authorizationNullifierHasher = Poseidon(3);
    authorizationNullifierHasher.inputs[0] <== secret;
    authorizationNullifierHasher.inputs[1] <== domain;
    authorizationNullifierHasher.inputs[2] <== nonce;
    authorizationNullifier <== authorizationNullifierHasher.out;

    component scopeNullifierHasher = Poseidon(2);
    scopeNullifierHasher.inputs[0] <== secret;
    scopeNullifierHasher.inputs[1] <== scope;
    scopeNullifier <== scopeNullifierHasher.out;
}

component main {public [messageHash, domain, nonce, scope]} = AFX1024();
