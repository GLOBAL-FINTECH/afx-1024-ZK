pragma circom 2.2.3;
include "circomlib/circuits/poseidon.circom";

// Proves a private secret authorizes a public message/domain/nonce tuple.
// commitment identifies the hidden credential; nullifier prevents replay.
template Authorization() {
    signal input secret;
    signal input salt;
    signal input messageHash;
    signal input domain;
    signal input nonce;
    signal output commitment;
    signal output authorizationTag;
    signal output nullifier;

    component c = Poseidon(2);
    c.inputs[0] <== secret;
    c.inputs[1] <== salt;
    commitment <== c.out;

    component a = Poseidon(4);
    a.inputs[0] <== secret;
    a.inputs[1] <== messageHash;
    a.inputs[2] <== domain;
    a.inputs[3] <== nonce;
    authorizationTag <== a.out;

    component n = Poseidon(3);
    n.inputs[0] <== secret;
    n.inputs[1] <== domain;
    n.inputs[2] <== nonce;
    nullifier <== n.out;
}
component main {public [messageHash, domain, nonce]} = Authorization();
