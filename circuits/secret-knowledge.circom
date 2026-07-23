pragma circom 2.2.3;
include "circomlib/circuits/poseidon.circom";

// Proves knowledge of private (secret, salt) opening a public commitment.
// Public outputs: commitment, nullifier. Public input: scope.
template SecretKnowledge() {
    signal input secret;
    signal input salt;
    signal input scope;
    signal output commitment;
    signal output nullifier;

    component c = Poseidon(2);
    c.inputs[0] <== secret;
    c.inputs[1] <== salt;
    commitment <== c.out;

    component n = Poseidon(2);
    n.inputs[0] <== secret;
    n.inputs[1] <== scope;
    nullifier <== n.out;
}
component main {public [scope]} = SecretKnowledge();
