# W3C Verifiable Credentials Data Model v2.0 Specification

**Status**: W3C Recommendation
**Source**: https://www.w3.org/TR/vc-data-model/
**Purpose**: Technical reference for formal specification in Lean

---

## 1. Abstract

Verifiable Credentials provide a mechanism to express credentials on the Web in a way that is:
- **Cryptographically secure**: Protected by digital signatures and proofs
- **Privacy-respecting**: Supports selective disclosure and minimizes correlation
- **Machine-verifiable**: Can be automatically verified by software

Verifiable Credentials represent statements made by an issuer about a subject (e.g., educational qualifications, government-issued IDs, healthcare data).

---

## 2. Ecosystem Roles

### 2.1 Core Roles

1. **Holder**: Entity that possesses one or more verifiable credentials and generates verifiable presentations
2. **Issuer**: Entity that creates verifiable credentials and transmits them to holders
3. **Subject**: Entity about which claims are made (often, but not always, the holder)
4. **Verifier**: Entity that receives verifiable presentations and verifies their authenticity

### 2.2 Role Relationships

- A holder is often, but not always, a subject of the verifiable credentials
- An issuer may be the subject of their own credential
- Multiple roles can be performed by the same entity

---

## 3. Core Data Model

### 3.1 Credential vs Verifiable Credential

**Credential**: A set of one or more claims made by the same entity.

**Verifiable Credential**: A credential that includes:
- The original claims
- Metadata about the credential
- A cryptographic proof (signature, etc.) that makes the credential tamper-evident and verifiable

### 3.2 Presentation vs Verifiable Presentation

**Presentation**: Data derived from one or more credentials, issued by one or more issuers, shared with a specific verifier.

**Verifiable Presentation**: A presentation that includes:
- One or more verifiable credentials
- Metadata about the presentation
- A cryptographic proof that makes the presentation tamper-evident and verifiable

---

## 4. Verifiable Credential Structure

### 4.1 Core Properties

A Verifiable Credential is a JSON-LD document with the following structure:

```json
{
  "@context": [...],              // REQUIRED
  "type": [...],                  // REQUIRED
  "id": "...",                    // OPTIONAL
  "name": "...",                  // OPTIONAL
  "description": "...",           // OPTIONAL
  "issuer": "..." | {...},        // REQUIRED
  "validFrom": "...",             // OPTIONAL (replaces issuanceDate in v1)
  "validUntil": "...",            // OPTIONAL (replaces expirationDate in v1)
  "credentialSubject": {...} | [...], // REQUIRED
  "credentialStatus": {...},      // OPTIONAL
  "credentialSchema": {...},      // OPTIONAL
  "evidence": [...],              // OPTIONAL
  "termsOfUse": [...],            // OPTIONAL
  "refreshService": {...},        // OPTIONAL
  "proof": {...} | [...]          // Securing mechanism (embedded or enveloped)
}
```

---

## 5. Property Specifications

### 5.1 `@context` (REQUIRED)

- **Type**: Ordered set of URIs or JSON-LD context objects
- **Requirement**: **MUST** be present in all verifiable credentials
- **Requirement**: The first item **MUST** be `https://www.w3.org/ns/credentials/v2`
- **Purpose**: Defines the semantic meaning of terms used in the credential

**Example**:
```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/2018/credentials/examples/v1"
  ]
}
```

### 5.2 `type` (REQUIRED)

- **Type**: Ordered set of strings (URIs)
- **Requirement**: **MUST** include at least the string `"VerifiableCredential"`
- **Purpose**: Expresses the type of credential
- **Note**: Additional types can be specified for domain-specific credentials

**Example**:
```json
{
  "type": ["VerifiableCredential", "UniversityDegreeCredential"]
}
```

### 5.3 `id` (OPTIONAL)

- **Type**: String (URI)
- **Requirement**: If present, **MUST** be a URI
- **Purpose**: Provides a globally unique identifier for the credential
- **Privacy Warning**: Identifiers can be harmful for privacy when pseudonymity is required

**Example**:
```json
{
  "id": "http://example.edu/credentials/3732"
}
```

or with UUID:
```json
{
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5"
}
```

### 5.4 `name` (OPTIONAL)

- **Type**: String
- **Purpose**: Human-readable name for the credential
- **Internationalization**: Supports language-tagged strings

**Example**:
```json
{
  "name": "University Degree"
}
```

### 5.5 `description` (OPTIONAL)

- **Type**: String
- **Purpose**: Human-readable description of the credential
- **Internationalization**: Supports language-tagged strings

**Example**:
```json
{
  "description": "Bachelor of Science and Arts degree in Computer Science"
}
```

### 5.6 `issuer` (REQUIRED)

- **Type**: String (URI) or Object
- **Requirement**: **MUST** be present
- **Purpose**: Identifies the entity that issued the credential

**As URI**:
```json
{
  "issuer": "https://example.edu/issuers/565049"
}
```

or with DID:
```json
{
  "issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f"
}
```

**As Object**:
```json
{
  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  }
}
```

When an object:
- **MUST** include an `id` property (URI)
- **MAY** include additional properties (name, description, etc.)

### 5.7 `validFrom` (OPTIONAL)

- **Type**: String (XML datetime)
- **Purpose**: Specifies when the credential becomes valid
- **Note**: In v1.x, this was called `issuanceDate` (REQUIRED in v1)

**Example**:
```json
{
  "validFrom": "2023-01-01T00:00:00Z"
}
```

### 5.8 `validUntil` (OPTIONAL)

- **Type**: String (XML datetime)
- **Purpose**: Specifies when the credential expires
- **Note**: In v1.x, this was called `expirationDate`

**Example**:
```json
{
  "validUntil": "2028-12-31T23:59:59Z"
}
```

### 5.9 `credentialSubject` (REQUIRED)

- **Type**: Object or Array of objects
- **Requirement**: **MUST** be present
- **Purpose**: Contains claims about the subject(s)

**Single Subject**:
```json
{
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
```

**Multiple Subjects**:
```json
{
  "credentialSubject": [
    {
      "id": "did:example:subject1",
      "name": "Alice"
    },
    {
      "id": "did:example:subject2",
      "name": "Bob"
    }
  ]
}
```

**Properties**:
- **MAY** include an `id` property (URI identifying the subject)
- **MUST** include at least one additional property (the claims)
- Properties are defined by the credential's context

### 5.10 `credentialStatus` (OPTIONAL)

- **Type**: Object
- **Purpose**: Provides information about the credential's revocation or suspension status

**Required Properties**:
- `id`: URI identifying the status information
- `type`: Status mechanism type

**Example (StatusList2021)**:
```json
{
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://example.edu/credentials/status/3"
  }
}
```

**Common Status Types**:
- `StatusList2021Entry`
- `BitstringStatusListEntry` (newer specification)
- Custom status mechanisms

### 5.11 `credentialSchema` (OPTIONAL)

- **Type**: Object or Array of objects
- **Purpose**: References a schema for validating the credential's structure

**Required Properties**:
- `id`: URI identifying the schema
- `type`: Schema type

**Example**:
```json
{
  "credentialSchema": {
    "id": "https://example.org/examples/degree.json",
    "type": "JsonSchema"
  }
}
```

### 5.12 `evidence` (OPTIONAL)

- **Type**: Array of objects
- **Purpose**: Provides supporting evidence for the claims

**Example**:
```json
{
  "evidence": [{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
    "type": ["DocumentVerification"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "DriversLicense",
    "subjectPresence": "Physical",
    "documentPresence": "Physical"
  }]
}
```

### 5.13 `termsOfUse` (OPTIONAL)

- **Type**: Array of objects
- **Purpose**: Defines terms under which the credential can be used

**Example**:
```json
{
  "termsOfUse": [{
    "type": "IssuerPolicy",
    "id": "https://example.edu/policies/usage",
    "profile": "https://example.edu/profiles/credential"
  }]
}
```

### 5.14 `refreshService` (OPTIONAL)

- **Type**: Object
- **Purpose**: Provides a mechanism for refreshing the credential

**Required Properties**:
- `id`: URI of the refresh service
- `type`: Service type

**Example**:
```json
{
  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
```

---

## 6. Securing Mechanisms (Proofs)

### 6.1 Proof Types

Verifiable Credentials **MUST** be secured by at least one of:
1. **Embedded Proofs** (Data Integrity)
2. **Enveloping Proofs** (JOSE/COSE)

### 6.2 Embedded Proofs (Data Integrity)

Embedded proofs are added as a `proof` property within the credential.

**Common Properties**:
- `type`: Proof type (e.g., `DataIntegrityProof`, `Ed25519Signature2020`)
- `created`: Timestamp of proof creation
- `verificationMethod`: URI identifying the verification method
- `proofPurpose`: Purpose of the proof (e.g., `assertionMethod`)
- `proofValue`: The cryptographic proof (signature)

**Example**:
```json
{
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-06-18T21:19:10Z",
    "verificationMethod": "https://example.edu/issuers/565049#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZoNVQPECZdVF..."
  }
}
```

**Multiple Proofs**:
```json
{
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2023-06-18T21:19:10Z",
      "verificationMethod": "did:example:issuer#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z3FXQ..."
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "bbs-2023",
      "created": "2023-06-18T21:19:10Z",
      "verificationMethod": "did:example:issuer#key-2",
      "proofPurpose": "assertionMethod",
      "proofValue": "u2V0C..."
    }
  ]
}
```

### 6.3 Enveloping Proofs (JOSE/COSE)

The entire credential is wrapped in a JSON Web Signature (JWS) or CBOR Object Signing and Encryption (COSE) structure.

**JOSE (JSON Web Signature)**:
- Uses compact JWS format
- Credential is the JWS payload
- Signature is in JWS header

**COSE (CBOR Object Signing)**:
- Uses CBOR encoding
- More compact than JSON
- Suitable for constrained environments

### 6.4 Zero-Knowledge Proofs

Some proof types support zero-knowledge proofs (ZKP):
- Allow selective disclosure of claims
- Prove statements without revealing underlying data
- Examples: BBS+ signatures, zk-SNARKs

---

## 7. Verifiable Presentation Structure

### 7.1 Core Properties

A Verifiable Presentation is a JSON-LD document with the following structure:

```json
{
  "@context": [...],                     // REQUIRED
  "type": [...],                         // REQUIRED
  "id": "...",                           // OPTIONAL
  "holder": "..." | {...},               // OPTIONAL
  "verifiableCredential": [...],         // OPTIONAL
  "proof": {...} | [...]                 // Securing mechanism
}
```

### 7.2 Property Specifications

#### 7.2.1 `@context` (REQUIRED)

- Same requirements as in Verifiable Credentials
- First item **MUST** be `https://www.w3.org/ns/credentials/v2`

#### 7.2.2 `type` (REQUIRED)

- **MUST** include at least the string `"VerifiablePresentation"`
- **MAY** include additional types

**Example**:
```json
{
  "type": ["VerifiablePresentation", "CredentialManagerPresentation"]
}
```

#### 7.2.3 `id` (OPTIONAL)

- URI identifying the presentation
- Same considerations as credential `id`

#### 7.2.4 `holder` (OPTIONAL)

- **Type**: String (URI) or Object
- **Purpose**: Identifies the entity presenting the credentials

**Example**:
```json
{
  "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
}
```

#### 7.2.5 `verifiableCredential` (OPTIONAL)

- **Type**: Array of Verifiable Credentials
- **Purpose**: Contains the credentials being presented

**Example**:
```json
{
  "verifiableCredential": [
    {
      "@context": [...],
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "issuer": "https://example.edu/issuers/565049",
      "credentialSubject": {...},
      "proof": {...}
    }
  ]
}
```

#### 7.2.6 `proof` (Securing Mechanism)

- Similar to credential proofs
- Proves the presentation was created by the holder
- **MAY** include challenge and domain properties to prevent replay attacks

**Example**:
```json
{
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-06-18T21:19:10Z",
    "verificationMethod": "did:example:holder#key-1",
    "proofPurpose": "authentication",
    "challenge": "1f44d55f-f161-4938-a659-f8026467f126",
    "domain": "example.verifier.com",
    "proofValue": "z5Afn..."
  }
}
```

### 7.3 Complete Presentation Example

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": ["VerifiablePresentation"],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "holder": "did:example:holder123",
  "verifiableCredential": [{
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": "https://example.edu/issuers/565049",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:holder123",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science in Computer Science"
      }
    },
    "proof": {
      "type": "DataIntegrityProof",
      "created": "2023-01-01T00:00:00Z",
      "verificationMethod": "https://example.edu/issuers/565049#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z3Fkd..."
    }
  }],
  "proof": {
    "type": "DataIntegrityProof",
    "created": "2023-06-18T21:19:10Z",
    "verificationMethod": "did:example:holder123#key-1",
    "proofPurpose": "authentication",
    "challenge": "1f44d55f-f161-4938-a659-f8026467f126",
    "domain": "example.verifier.com",
    "proofValue": "z5Afn..."
  }
}
```

---

## 8. Validation and Verification

### 8.1 Validation vs Verification

**Validation**: Checking that the credential conforms to the specification (structure, required fields, etc.)

**Verification**: Cryptographically checking the authenticity and integrity of the credential

### 8.2 Validation Checks

A conformant verifier **SHOULD** perform the following validation checks:

1. **Credential Type**: Ensure `type` includes `"VerifiableCredential"`
2. **Context**: Ensure `@context` is present and first item is correct
3. **Credential Subject**: Ensure `credentialSubject` is present
4. **Issuer**: Ensure `issuer` is present and valid
5. **Issuance/Validity**: Check `validFrom`/`validUntil` dates
6. **Status**: Check credential status (if present)
7. **Schema**: Validate against schema (if present)
8. **Proof Structure**: Ensure proof is present and well-formed

### 8.3 Verification Checks

A conformant verifier **MUST** perform the following verification checks:

1. **Proof Verification**: Cryptographically verify the signature/proof
2. **Issuer Authentication**: Verify the issuer's identity
3. **Key Validity**: Ensure signing key is valid for the issuer
4. **Not Expired**: Check validity period
5. **Not Revoked**: Check credential status

### 8.4 Verification Algorithm (High-Level)

```
function verify(credential):
  1. Validate structure (conformance checks)
  2. Resolve issuer identifier to get verification methods
  3. Extract proof from credential
  4. Verify proof using issuer's public key
  5. Check validity dates (validFrom, validUntil)
  6. Check credential status (if present)
  7. Validate against schema (if present)
  8. Return verification result
```

---

## 9. Status Mechanisms

### 9.1 Status List 2021

A bitstring-based revocation mechanism where each credential is assigned a position in a bitstring.

**Properties**:
- `statusPurpose`: "revocation" or "suspension"
- `statusListIndex`: Position in the bitstring
- `statusListCredential`: URI of the status list credential

**Example**:
```json
{
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://example.edu/credentials/status/3"
  }
}
```

### 9.2 Bitstring Status List (Newer)

Similar to StatusList2021 but with updated terminology.

**Properties**:
- `statusPurpose`: Purpose of the status (revocation, suspension, etc.)
- `statusListIndex`: Index in the bitstring
- `statusListCredential`: URI of the status list

### 9.3 Custom Status Mechanisms

Implementations **MAY** define custom status mechanisms with:
- `id`: URI identifying the status resource
- `type`: Custom status type
- Additional properties as needed

---

## 10. Security Considerations

### 10.1 Key Management

- Private keys **MUST** be kept secure
- Key rotation **SHOULD** be supported
- Compromised keys **MUST** be revocable

### 10.2 Man-in-the-Middle Attacks

- Credentials **SHOULD** be transmitted over secure channels (HTTPS, TLS)
- Proof mechanisms **SHOULD** include replay attack prevention (challenge, nonce)

### 10.3 Content Integrity

- All credentials **MUST** be secured with cryptographic proofs
- Modifications to credentials **MUST** invalidate the proof
- Verifiers **MUST** check proofs before trusting credentials

### 10.4 Replay Attacks

- Presentations **SHOULD** include `challenge` and `domain` in proofs
- Challenge **SHOULD** be freshly generated by the verifier
- Domain **SHOULD** be verified by the holder

### 10.5 Credential Theft

- Credentials **SHOULD** bind the holder to the credential
- Biometric binding **MAY** be used for high-security credentials
- Holder binding **SHOULD** be verified during presentation

---

## 11. Privacy Considerations

### 11.1 Identifier-Based Correlation

- **Problem**: Identifiers in `id`, `issuer`, `credentialSubject.id` can be used to correlate credentials
- **Mitigation**: Use pairwise DIDs, avoid reusing identifiers across contexts

### 11.2 Signature-Based Correlation

- **Problem**: Standard signatures link all uses of the same credential
- **Mitigation**: Use ZKP-based signatures (BBS+), selective disclosure, unlinkable presentations

### 11.3 Long-Lived Identifiers

- **Problem**: Long-lived identifiers increase correlation risk
- **Mitigation**: Use ephemeral identifiers, rotate identifiers regularly

### 11.4 Biometric Data

- **Requirement**: Biometric data **MUST NOT** be included in credentials
- **Mitigation**: Use biometric templates, store biometrics locally only

### 11.5 Data Minimization

- Credentials **SHOULD** contain only necessary claims
- Selective disclosure **SHOULD** be supported
- Verifiers **SHOULD** request only necessary information

### 11.6 Herd Privacy

- Credentials **SHOULD** be designed to be common across many holders
- Unique identifiers **SHOULD** be avoided when possible
- Statistical anonymity **SHOULD** be considered

---

## 12. Conformance

### 12.1 Conformant Credential

A conformant verifiable credential:
- **MUST** include `@context` with correct first item
- **MUST** include `type` with `"VerifiableCredential"`
- **MUST** include `issuer`
- **MUST** include `credentialSubject`
- **MUST** be secured by at least one proof mechanism
- **MUST** be valid JSON-LD
- If `id` is present, **MUST** be a URI
- If `validFrom`/`validUntil` present, **MUST** be XML datetime
- If `credentialStatus` present, **MUST** include `id` and `type`
- If `credentialSchema` present, **MUST** include `id` and `type`

### 12.2 Conformant Presentation

A conformant verifiable presentation:
- **MUST** include `@context` with correct first item
- **MUST** include `type` with `"VerifiablePresentation"`
- **MUST** be secured by at least one proof mechanism
- **MUST** be valid JSON-LD
- If `verifiableCredential` present, each **MUST** be a conformant credential
- If `holder` present, **SHOULD** be a URI

### 12.3 Conformant Issuer

A conformant issuer:
- **MUST** produce conformant credentials
- **MUST** secure credentials with at least one proof mechanism
- **SHOULD** support credential status mechanisms
- **SHOULD** provide status information

### 12.4 Conformant Verifier

A conformant verifier:
- **MUST** verify cryptographic proofs
- **MUST** validate credential structure
- **SHOULD** check credential status
- **SHOULD** validate against schemas
- **SHOULD** check validity periods
- **MUST** reject invalid credentials

### 12.5 Conformant Holder

A conformant holder:
- **MUST** produce conformant presentations
- **MUST** secure presentations with proofs
- **SHOULD** implement selective disclosure
- **SHOULD** verify received credentials before storing

---

## 13. MUST/SHOULD/MAY Summary

### 13.1 MUST Requirements (Normative)

1. Credential **MUST** include `@context` property
2. First `@context` item **MUST** be `https://www.w3.org/ns/credentials/v2`
3. Credential **MUST** include `type` with `"VerifiableCredential"`
4. Credential **MUST** include `issuer` property
5. Credential **MUST** include `credentialSubject` property
6. Credential **MUST** be secured by at least one proof mechanism
7. Credential **MUST** be valid JSON-LD
8. `id` property **MUST** be a URI (if present)
9. `issuer` **MUST** be a URI or object with `id` (if object)
10. Verifier **MUST** verify cryptographic proofs
11. Verifier **MUST** reject credentials with invalid proofs
12. Biometric data **MUST NOT** be included in credentials
13. Private keys **MUST** be kept secure
14. Private keys **MUST NOT** be included in credentials
15. Modifications **MUST** invalidate proofs
16. `credentialStatus` **MUST** include `id` and `type` (if present)
17. `credentialSchema` **MUST** include `id` and `type` (if present)

### 13.2 SHOULD Requirements (Recommended)

1. Issuer **SHOULD** support credential status mechanisms
2. Verifier **SHOULD** check credential status
3. Verifier **SHOULD** validate against schemas
4. Verifier **SHOULD** check validity periods
5. Credentials **SHOULD** be transmitted over secure channels
6. Presentations **SHOULD** include challenge and domain
7. Credentials **SHOULD** bind holder to credential
8. Holder binding **SHOULD** be verified
9. Key rotation **SHOULD** be supported
10. Credentials **SHOULD** contain only necessary claims
11. Selective disclosure **SHOULD** be supported
12. Verifiers **SHOULD** request only necessary information
13. Credentials **SHOULD** be common across many holders
14. Identifiers **SHOULD** be rotated regularly
15. Pairwise DIDs **SHOULD** be used for sensitive interactions

### 13.3 MAY Requirements (Optional)

1. Credential **MAY** include `id` property
2. Credential **MAY** include `name` property
3. Credential **MAY** include `description` property
4. Credential **MAY** include `validFrom`/`validUntil`
5. Credential **MAY** include `credentialStatus`
6. Credential **MAY** include `credentialSchema`
7. Credential **MAY** include `evidence`
8. Credential **MAY** include `termsOfUse`
9. Credential **MAY** include `refreshService`
10. Issuer **MAY** include additional properties (when object)
11. Proof **MAY** include multiple proofs
12. Custom status mechanisms **MAY** be defined
13. Biometric binding **MAY** be used

---

## 14. Key Concepts for Formalization

### 14.1 Type System

```
Credential = Map<String, Value>
VerifiableCredential = Credential + Proof
Presentation = Map<String, Value>
VerifiablePresentation = Presentation + Proof
Proof = Map<String, Value>
Value = String | Number | Boolean | Map | Array | Null
```

### 14.2 Validation Predicates

```
isValidCredential(vc: VerifiableCredential) -> Boolean
  = hasContext(vc) '
    contextValid(vc) '
    hasType(vc, "VerifiableCredential") '
    hasIssuer(vc) '
    hasCredentialSubject(vc) '
    hasProof(vc) '
    isValidJSONLD(vc)

verifyCredential(vc: VerifiableCredential, issuerPublicKey: PublicKey) -> Boolean
  = isValidCredential(vc) '
    verifyProof(vc.proof, vc, issuerPublicKey) '
    checkValidity(vc) '
    checkStatus(vc)

isValidPresentation(vp: VerifiablePresentation) -> Boolean
  = hasContext(vp) '
    contextValid(vp) '
    hasType(vp, "VerifiablePresentation") '
    hasProof(vp) '
    allCredentialsValid(vp.verifiableCredential)
```

### 14.3 Core Invariants

1. **Proof Integrity**: Any modification to a credential invalidates its proof
2. **Issuer Binding**: Each credential is bound to its issuer via proof
3. **Subject Claims**: Credentials contain at least one claim about the subject
4. **Temporal Validity**: Credentials are only valid within their validity period
5. **Status Consistency**: Revoked/suspended credentials fail verification

---

## 15. Notes for Lean Formalization

### 15.1 Challenges

1. **JSON-LD Processing**: Full JSON-LD semantics are complex (may need axioms)
2. **Extensibility**: Credentials support arbitrary properties via contexts
3. **Cryptographic Operations**: Proof verification depends on cryptographic primitives
4. **External Dependencies**: Status checking requires network access

### 15.2 Recommended Approach

1. **Core Types**: Define inductive types for Credential, VerifiableCredential, Presentation
2. **Required Properties**: Model as record types with required fields
3. **Optional Properties**: Model using Option types
4. **Proofs**: Abstract proof verification as axioms or external functions
5. **Validation**: Define predicates for structure validation
6. **Verification**: Define predicates for cryptographic verification
7. **Invariants**: State and prove key security/privacy properties

### 15.3 Abstraction Layers

```
Layer 1: Data Model (JSON-LD structures, properties)
Layer 2: Validation (structural correctness)
Layer 3: Proofs (cryptographic securing)
Layer 4: Verification (authenticity checking)
Layer 5: Security Properties (integrity, authenticity, non-repudiation)
Layer 6: Privacy Properties (unlinkability, selective disclosure)
```

### 15.4 Dependencies on External Specifications

- **DID**: Issuer, subject, holder identifiers often use DIDs
- **Proof Formats**: Data Integrity, JOSE, COSE specifications
- **Cryptographic Primitives**: Signature schemes, hash functions
- **Status Mechanisms**: StatusList2021, BitstringStatusList

### 15.5 Formalization Strategy

1. **Start with Core Model**: Define basic credential structure
2. **Add Required Properties**: Model MUST requirements
3. **Define Validation**: Implement structure validation predicates
4. **Abstract Crypto**: Use axioms for proof verification
5. **State Invariants**: Formalize security properties
6. **Prove Theorems**: Show properties hold under assumptions

---

## 16. Examples

### 16.1 Simple Credential

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": ["VerifiableCredential", "AlumniCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": "Example University"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-01-01T00:00:00Z",
    "verificationMethod": "https://example.edu/issuers/565049#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FkdP4..."
  }
}
```

### 16.2 Credential with Status

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:example:issuer",
  "validFrom": "2023-01-01T00:00:00Z",
  "validUntil": "2028-12-31T23:59:59Z",
  "credentialSubject": {
    "id": "did:example:holder",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science in Computer Science"
    }
  },
  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://example.edu/credentials/status/3"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2023-01-01T00:00:00Z",
    "verificationMethod": "did:example:issuer#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5Afn2..."
  }
}
```

### 16.3 Selective Disclosure Credential (BBS+)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "type": ["VerifiableCredential", "PersonCredential"],
  "issuer": "did:example:issuer",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:holder",
    "name": "Alice Smith",
    "age": 30,
    "country": "United States",
    "email": "alice@example.com"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "bbs-2023",
    "created": "2023-01-01T00:00:00Z",
    "verificationMethod": "did:example:issuer#key-2",
    "proofPurpose": "assertionMethod",
    "proofValue": "u2V0ChVh..."
  }
}
```

---

## 17. References

- W3C Verifiable Credentials Data Model v2.0: https://www.w3.org/TR/vc-data-model/
- W3C Verifiable Credentials Data Model v1.1: https://www.w3.org/TR/vc-data-model-1.1/
- Data Integrity: https://www.w3.org/TR/vc-data-integrity/
- JSON-LD 1.1: https://www.w3.org/TR/json-ld11/
- StatusList2021: https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/
- BitstringStatusList: https://www.w3.org/TR/vc-bitstring-status-list/
- JOSE (RFC 7515): https://tools.ietf.org/html/rfc7515
- COSE (RFC 8152): https://tools.ietf.org/html/rfc8152
