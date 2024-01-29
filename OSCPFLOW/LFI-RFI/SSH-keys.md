# SSH Keys
## Key Types (RSA, DSA, ECDSA, EdDSA)
```
RSA, DSA, ECDSA, or EdDSA?
Encryption Within the SSH Protocol
SSH is used almost universally to connect to shells on remote machines.
The most important part of an SSH session is establishing a secure connection. This happens in two broad steps:
    Negotiation & Connection
    Authentication
```

## Asymmetric Encryption Algorithms
```
What makes asymmetric encryption powerful is that a private key can be used to derive a paired public key, but not the other way around.
This principle is core to public-key authentication. If Alice had used a weak encryption algorithm that could be brute-forced by today's processing capabilities, a third party could derive Alice's private key using her public key. Protecting against a threat like this requires selection of the right algorithm.

There are three classes of these algorithms commonly used for asymmetric encryption: RSA, DSA, and elliptic curve based algorithms.
To properly evaluate the strength and integrity of each algorithm, it is necessary to understand the mathematics that constitutes the core of each algorithm.
```

## RSA: Integer Factorization
```
First used in 1978, the RSA cryptography is based on the held belief that factoring large semi-prime numbers is difficult by nature. Given that no general-purpose formula has been found to factor a compound number into its prime factors, there is a direct relationship between the size of the factors chosen and the time required to compute the solution. In other words, given a number n=p\*q where p and q are sufficiently large prime numbers, it can be assumed that anyone who can factor n into its component parts is the only party that knows the values of p and q. The same logic exists for public and private keys. In fact, p & q are necessary variables for the creation of a private key, and n is a variable for the subsequent public key. This presentation simplifies RSA integer factorization
```

## DSA: Discrete Logarithm Problem & Modular Exponentiation
```
DSA follows a similar schema, as RSA with public/private keypairs that are mathematically related. What makes DSA different from RSA is that DSA uses a different algorithm. It solves an entirely different problem using different elements, equations, and steps. While the discrete log problem is fun, it is out of scope for this post. What is important to note is the use of a randomly generated number, m, is used with signing a message along with a private key, k. This number m must be kept private.
```

## ECDSA & EdDSA: Elliptic Curve Discrete Logarithm Problem
```
Algorithms using elliptic curves are also based on the assumption that there is no generally efficient solution to solving a discrete log problem. However, ECDSA/EdDSA and DSA differ in that DSA uses a mathematical operation known as modular exponentiation while ECDSA/EdDSA uses elliptic curves. The computational complexity of the discrete log problem allows both classes of algorithms to achieve the same level of security as RSA with significantly smaller keys.
```

## Comparing Encryption Algorithms
```
Choosing the right algorithm depends on a few criteria:

    Implementation - Can the experts handle it, or does it need to be rolled?
    Compatibility - Are there SSH clients that do not support a method?
    Performance - How long will it take to generate a sufficiently secure key?
    Security - Can the public key be derived from the private key? (The use of quantum computing to break encryption is not discussed in this article.)

RSA
Most widely implemented and supported.
Larger keys require more time to generate.
Specialized algorithms like Quadratic Sieve and General Number Field Sieve exist to factor integers with specific qualities.

DSA
Its notorious security history makes it less popular.
Faster for signature generation but slower for validation.
DSA requires the use of a randomly generated unpredictable and secret value that, if discovered, can reveal the private key.

ECDSA
Fairly new but not as popular as EdDSA.
Public keys are twice the length of the desired bit security.
Vulnerable if pseudo random number aren't cryptographically strong.

EdDSA
Fairly new but favoured by most modern cryptographic libraries.
EdDSA is the fastest performing algorithm across all metrics.
EdDSA provides the highest security level compared to key length. It also improves on the insecurities found in ECDSA.

The choice is between RSA 2048/4096 and Ed25519 and the trade-off is between performance and compatibility.
RSA is universally supported among SSH clients while EdDSA performs much faster and provides the same level of security with significantly smaller keys.
Peter Ruppel puts the answer succinctly:
    The short answer to this is: as long as the key strength is good enough for the foreseeable future, it doesn't really matter. Because here we are considering a signature for authentication within an SSH session. The cryptographic strength of the signature just needs to withstand the current, state-of-the-art attacks.

```

## Generate SSH keys 
```
How to generate SSH Keys
The SSH key generation process is handled by the OpenSSH helper program ssh-keygen. The types of keys supported by OpenSSH are:

    dsa: Key generated with Discrete Logarithm Problem & Modular Exponentiation algorithm.
    ecdsa: Key generated with Elliptic Curve Discrete Logarithm Problem algorithm.
    ecdsa-sk: Same as ecdsa but with an option to store the keys in FIDO/U2F devices.
    ed25519: Key generated with Edwards-curve Digital Signature algorithm.
    ed25519-sk: Same as ed25519 but with an option to store the keys in FIDO/U2F devices.
    rsa: Key generated with Rivest–Shamir–Adleman algorithm.

So what is the recommended SSH key generation algorithm?
The two most popular options for key generation are either rsa or ed25519.
The ed25519 algorithm offers more cryptographically strong keys while rsa is the most widely supported algorithm.
If you are generating a key for modern SSH servers, go with ed25519.

To generate an SSH key of type ed25519, we invoke the ssh-keygen command with a -t flag as follows:
$ ssh-keygen -t ed25519 -C "unique name to identify this key"

The default key size is 256 bits. To use higher bits, you can use the -b flag as the following:
$ ssh-keygen -t rsa -b 4096

By default, SSH keys are placed in the ~/.ssh/ directory, but this is optional and you can place them anywhere you want to.
```

## Certificates better than keys
```
Although keys are a relatively secure authentication method for SSH when compared with password-based authentication, keys create an equal amount of operational and security overhead on the administration side.
Key rotation and key invalidation remain a challenge that can be resolved using certificate-based authentication. 
```













