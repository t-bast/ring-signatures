# Ring Signatures

Implementations of Ring Signature schemes.
See [How to Leak a Secret](https://people.csail.mit.edu/rivest/pubs/RST01.pdf) for the original paper.

The paper describes ring signatures using RSA, but this repository implements ring signatures using elliptic curves instead, based on Schnorr signatures.

## Disclaimer

Note that this implementation didn't go through a proper cryptographic audit.
It's most likely not secure for real-world use.
It hasn't been performance-tested either, so it's probably not the most performant implementation you could find either.
If you do look at the code and find security issues, please open an issue: I would be really interested in understanding what could go wrong and fixing it (and maybe eventually this will become a usable implementation, who knows?).
