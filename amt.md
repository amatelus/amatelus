# The did:amt Method Specification

**バージョン: 1**  
**言語: earth:en**  
**ライセンス: CC0-1.0**  
**HTTP URL: https://kuuga.io/papers/bafybeibgmzkthatdqxkpzjbrnk6g4zjjynthtynourn5hhku7ef3vvcydm **  
**IPFS URI: ipfs://bafybeibgmzkthatdqxkpzjbrnk6g4zjjynthtynourn5hhku7ef3vvcydm **  
**公開日: 2025年7月2日**  
**著者:**
- Mitsuhide Matsuda
- Gemini 2.5 Pro

**参考文献:**
- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Base 32](https://www.crockford.com/base32.html)
- [The Multibase Data Format](https://datatracker.ietf.org/doc/html/draft-multiformats-multibase)
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://tools.ietf.org/html/rfc8785)
- [null](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

## Abstract

The `did:amt` method specifies a Decentralized Identifier (DID) that is algorithmically generated and resolved without reliance on any external Verifiable Data Registry (VDR) such as a blockchain. This method is based on the **AMT (Autonomous Meta-Trust) Protocol**, designed for high-stakes environments like public administration, where data integrity and operational robustness are paramount.

This document proposes the initial version, **`did:amt` Version 0**.

In Version 0, to ensure the permanent uniqueness of the identifier itself, a Post-Quantum Cryptography (PQC) resistant hash function (SHA3-512) is employed. Concurrently, considering current implementation efficiency and technological maturity, the widely adopted classical cryptography (Ed25519) is used for the signature method to prove ownership of the DID. Furthermore, to minimize human error during manual transcription in administrative processes, **Crockford's Base32** encoding is adopted for both the DID's method-specific-id and the public key representation.

The AMT protocol incorporates "cryptographic agility" in its design, allowing for the upgrade of its cryptographic suite, including the signature scheme, to be PQC-compliant in the future to counter emerging threats from quantum computers.

## Status of This Document

This document is a draft of a specification for the `did:amt` DID method. It is subject to change and is not a W3C Standard.

## 1. The `did:amt` Method Specification (Version 0)

This section defines the technical details of the proposed specification, Version 0.

### 1.1. `did:amt` Method Syntax

The `did:amt` syntax conforms to the W3C DID Core specification.

```
did-amt              := "did:amt:" method-specific-id
method-specific-id   := crockford-base32-encoded-sha3-512-hash
```

The `method-specific-id` is a **Crockford's Base32** encoded string of the hash value generated through the process defined in **1.2.1. Create**.

**Crockford's Base32 Character Set:**
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`

### 1.2. CRUD Operations for Version 0

#### 1.2.1. Create

A `did:amt` identifier is generated locally on the owner's device. No network registration is required.

1.  **Generate Key Pair:** The owner generates an **Ed25519** key pair.
2.  **Prepare Information Pair:** The owner prepares the following information pair:
      * `AMT Version Number`: Specify `0` for Version 0.
      * `Public Key`: The generated Ed25519 public key.
3.  **Select DID Document Template:** A standardized DID Document template corresponding to the `AMT Version Number` is selected.
      * **AMT Version 0 Template Example:**
        ```json
        {
          "@context": ["https://www.w3.org/ns/did/v1"],
          "verificationMethod": [
            {
              "type": "Ed25519VerificationKey2020",
              "publicKeyMultibase": "<multibase-encoded-public-key>"
            }
          ],
          "authentication": ["#key-1"],
          "assertionMethod": ["#key-1"]
        }
        ```
4.  **Derive DID:**
    a. The Ed25519 public key is encoded in `publicKeyMultibase` format, by **applying Crockford's Base32 encoding and prepending the `k` prefix**.
    b. This value is inserted into the `publicKeyMultibase` field of the template.
    c. The entire template JSON object, now containing the public key, is normalized (e.g., using JCS - RFC 8785) and then hashed using the **SHA3-512** algorithm.
    d. The resulting hash digest is encoded using **Crockford's Base32**. This string becomes the `method-specific-id`.
    e. The full DID is constructed by prepending `did:amt:` to the `method-specific-id`.
5.  **Finalize DID Document:**
    The DID derived in the previous step is used to populate the `id`, `controller`, and `verificationMethod.id` fields in the DID Document, creating the final, complete document.

#### 1.2.2. Read

The resolution of a `did:amt` is completed locally by a verifier who receives the `[AMT Version Number, Public Key]` pair from the owner and executes the same steps from 1.2.1, step 3 onwards.

#### 1.2.3. Update

As `did:amt` DID Documents are immutable, **Update operations are not supported.** Key rotation is handled by re-issuing a new DID and linking it via a "DID Continuity Verifiable Credential" issued by a trusted third party.

#### 1.2.4. Deactivate

There is no explicit Deactivate operation. Deactivation is effectively achieved by destroying the associated private key.

## 2. Future Evolution and PQC Transition

This section describes the future outlook for the `did:amt` method and is not part of the normative specification for Version 0.

### 2.1. The Need for Transition

`did:amt` Version 0 intentionally adopts a classical cryptographic algorithm (Ed25519) for its signature scheme to prioritize current efficiency and ease of implementation. However, this signature scheme is not secure against future practical quantum computers.

The AMT protocol is designed with "cryptographic agility," allowing for the upgrade of its cryptographic suite through versioning to address such future threats. The version number is the key mechanism to manage this evolution.

### 2.2. Foreseeable Changes in Future Versions (AMT v1 and beyond)

#### 2.2.1. Adoption of PQC Signatures

The most critical change in future versions (e.g., AMT v1) will be the migration of the signature algorithm from Ed25519 to a **PQC signature algorithm** (e.g., CRYSTALS-Dilithium) selected by NIST. This will ensure that the proof of DID ownership is also secure against quantum computers.

#### 2.2.2. The Data Format Challenge and Binary Representations

PQC signature algorithms are characterized by significantly larger public key and signature sizes (ranging from several to tens of kilobytes) compared to classical cryptography. Handling such large data sizes within the current text-based (JSON-LD) DID Document format is impractical due to limitations in QR codes, URL lengths, and other mediums.

To address this challenge, it is highly likely that future versions of the `did:amt` method will specify a binary representation format, such as **CBOR (Concise Binary Object Representation)**, for its DID Documents to maintain efficiency while enabling the transition to PQC.

### 2.3. Interoperability Through Versioning

The `AMT Version Number` (`0`, `1`, `2`...) presented by the owner allows verifiers to accurately determine which cryptographic algorithms (Ed25519 or PQC signatures) and data formats (JSON-LD or CBOR) to use. This ensures secure interoperability during transition periods when DIDs of different versions coexist.

## 3. Example (Version 0)

This section provides a concrete example of creating a `did:amt` Version 0 identifier and its corresponding DID Document.

1.  **Holder's Information:**

      * AMT Version: `0`
      * Key Type: `Ed25519`
      * Public Key (32 bytes, hex): `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`

2.  **Encode Public Key:**

      * The 32-byte public key is encoded using Crockford's Base32, resulting in a 52-character string.
      * The multibase prefix `k` is prepended.
      * `publicKeyMultibase`: `k3t635r7r1c0kdf41n2p5h3t2d3n2g5r4g3t2e1d3k4j4f5h5j5` (Example value)

3.  **Derive DID:**

      * The `publicKeyMultibase` value is inserted into the Version 0 template.
      * The template is normalized and hashed with SHA3-512, resulting in a 64-byte hash digest.
      * The hash digest is encoded using Crockford's Base32, resulting in a 103-character string.
      * `method-specific-id`: `0V3R4T7K1Q2P3N4M5J6H7G8F5D4C3B2A1Z2Y3X4W5V6T7S8R9` (Example value, checksum not included)
      * Full Derived DID: `did:amt:0V3R4T7K1Q2P3N4M5J6H7G8F5D4C3B2A1Z2Y3X4W5V6T7S8R9`

4.  **Final DID Document:**
    The final, complete DID Document is constructed as follows:

    ```json
    {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:amt:0V3R4T7K1Q2P3N4M5J6H7G8F5D4C3B2A1Z2Y3X4W5V6T7S8R9",
      "verificationMethod": [
        {
          "id": "did:amt:0V3R4T7K1Q2P3N4M5J6H7G8F5D4C3B2A1Z2Y3X4W5V6T7S8R9#key-1",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:amt:0V3R4T7K1Q2P3N4M5J6H7G8F5D4C3B2A1Z2Y3X4W5V6T7S8R9",
          "publicKeyMultibase": "k3t635r7r1c0kdf41n2p5h3t2d3n2g5r4g3t2e1d3k4j4f5h5j5"
        }
      ],
      "authentication": [
        "#key-1"
      ],
      "assertionMethod": [
        "#key-1"
      ]
    }
    ```

## 4. Security, Privacy, and Robustness Considerations (Version 0)

(Content moved from former section 1.3 to here for structural clarity, text remains the same as previously defined).

### 4.1. Security

Version 0 ensures PQC-level collision resistance for the DID identifier itself via SHA3-512. The signature for proving DID ownership relies on Ed25519, which is extremely secure against current classical computers but is vulnerable to future quantum computers (see Section 2).

### 4.2. Privacy

The avoidance of a VDR ensures that DIDs are not publicly enumerable, providing a high degree of privacy.

### 4.3. Operational Robustness

This method mandates the use of Crockford's Base32 encoding for the DID's `method-specific-id` to minimize human errors (e.g., misreading `O` for `0` or `I` for `l`) during manual transcription in administrative settings, thereby ensuring operational safety. The combined use of an optional checksum is strongly recommended.
