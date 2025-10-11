# W3C Decentralized Identifiers (DIDs) v1.0 Specification

**Status**: W3C Recommendation
**Source**: https://www.w3.org/TR/did-core/
**Purpose**: Technical reference for formal specification in Lean

---

## 1. Abstract

Decentralized Identifiers (DIDs) are a new type of identifier that enables verifiable, decentralized digital identity. DIDs are:
- Globally unique
- Resolvable with high availability
- Cryptographically verifiable
- Controlled by the DID subject (individual, organization, thing, data model, etc.)
- Not dependent on centralized registries, identity providers, or certificate authorities

---

## 2. DID Syntax

### 2.1 DID Syntax ABNF

```abnf
did                = "did:" method-name ":" method-specific-id
method-name        = 1*method-char
method-char        = %x61-7A / DIGIT  ; lowercase letters (a-z) and digits (0-9)
method-specific-id = *( *idchar ":" ) 1*idchar
idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
pct-encoded        = "%" HEXDIG HEXDIG
```

### 2.2 DID Syntax Requirements

- A DID **MUST** be a single string composed of three parts: scheme, method-name, method-specific-id
- The scheme **MUST** be the string `did:`
- The method-name **MUST** be one or more lowercase letters or digits
- The method-specific-id **MUST** be specified by the DID method
- A DID **MUST** be case-sensitive
- A DID **MAY** be case-normalized for comparison purposes

### 2.3 Examples

Valid DIDs:
- `did:example:123456789abcdefghi`
- `did:example:123456789abcdefghi;version-id=1`
- `did:example:123`
- `did:web:example.com`

---

## 3. DID URL Syntax

### 3.1 DID URL Syntax ABNF

```abnf
did-url = did [ "/" path ] [ "?" query ] [ "#" fragment ]
path    = *( "/" segment )
query   = *( pchar / "/" / "?" )
fragment = *( pchar / "/" / "?" )
```

### 3.2 DID URL Parameters

A DID URL **MAY** contain query parameters:
- `service`: Selects a service endpoint from the DID document
- `versionId`: Requests a specific version of a DID document
- `versionTime`: Requests a version at a specific time
- `hl`: Hash link for resource integrity

---

## 4. DID Document Data Model

### 4.1 Core Data Types

The DID document data model supports:
- **Maps**: Unordered key-value pairs (keys are strings)
- **Lists**: Ordered sequences of values
- **Sets**: Unordered collections of unique values
- **Strings**: Sequences of Unicode characters
- **Integers**: Whole numbers
- **Doubles**: IEEE 754 double-precision numbers
- **Booleans**: `true` or `false`
- **Datetime**: XML datetime values
- **Null**: Absence of a value

### 4.2 DID Document Structure

A DID document is a map containing:

```
{
  "id": <DID>,                          // REQUIRED
  "alsoKnownAs": [<URI>, ...],         // OPTIONAL
  "controller": <DID> | [<DID>, ...],  // OPTIONAL
  "verificationMethod": [...],         // OPTIONAL
  "authentication": [...],             // OPTIONAL
  "assertionMethod": [...],            // OPTIONAL
  "keyAgreement": [...],               // OPTIONAL
  "capabilityInvocation": [...],       // OPTIONAL
  "capabilityDelegation": [...],       // OPTIONAL
  "service": [...]                     // OPTIONAL
}
```

---

## 5. DID Document Properties

### 5.1 `id` Property (REQUIRED)

- **Type**: String
- **Requirement**: **MUST** be a string that conforms to DID Syntax (Section 2.1)
- **Requirement**: **MUST** exist in the root map of the DID document
- **Purpose**: Identifies the DID subject

**Example**:
```json
{
  "id": "did:example:123456789abcdefghi"
}
```

### 5.2 `alsoKnownAs` Property (OPTIONAL)

- **Type**: Set of strings (URIs)
- **Purpose**: Lists alternative identifiers for the DID subject
- **Requirement**: Each value **MUST** be a valid URI

**Example**:
```json
{
  "id": "did:example:123",
  "alsoKnownAs": [
    "https://example.com/user/123",
    "did:web:example.com:user:123"
  ]
}
```

### 5.3 `controller` Property (OPTIONAL)

- **Type**: String (DID) or Set of strings (DIDs)
- **Purpose**: Identifies entities authorized to make changes to the DID document
- **Requirement**: Each value **MUST** be a valid DID
- **Requirement**: **SHOULD** contain verification methods for the controller(s)

**Example**:
```json
{
  "id": "did:example:123",
  "controller": "did:example:456"
}
```

or:

```json
{
  "id": "did:example:123",
  "controller": [
    "did:example:456",
    "did:example:789"
  ]
}
```

### 5.4 `verificationMethod` Property (OPTIONAL)

- **Type**: Set of verification method maps
- **Purpose**: Defines cryptographic material for verification
- **Requirement**: Each verification method **MUST** contain specific properties (see Section 6)

**Example**:
```json
{
  "id": "did:example:123",
  "verificationMethod": [{
    "id": "did:example:123#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}
```

### 5.5 Verification Relationships (OPTIONAL)

All verification relationships share common semantics:
- **Type**: Set of verification methods or DID URLs referencing verification methods
- **Purpose**: Express the relationship between the DID subject and verification methods

#### 5.5.1 `authentication`
- **Purpose**: Verification methods for authentication purposes
- **Requirement**: Each entry **MUST** be either a verification method map or a string (DID URL)

#### 5.5.2 `assertionMethod`
- **Purpose**: Verification methods for issuing credentials or making assertions

#### 5.5.3 `keyAgreement`
- **Purpose**: Verification methods for key agreement protocols (e.g., establishing secure communication)

#### 5.5.4 `capabilityInvocation`
- **Purpose**: Verification methods for invoking cryptographic capabilities

#### 5.5.5 `capabilityDelegation`
- **Purpose**: Verification methods for delegating cryptographic capabilities

**Example**:
```json
{
  "id": "did:example:123",
  "authentication": [
    "did:example:123#key-1",
    {
      "id": "did:example:123#key-2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:example:123",
      "publicKeyMultibase": "z6Mkw..."
    }
  ]
}
```

### 5.6 `service` Property (OPTIONAL)

- **Type**: Set of service endpoint maps
- **Purpose**: Defines service endpoints for interacting with the DID subject
- **Requirement**: Each service endpoint **MUST** contain specific properties (see Section 7)

**Example**:
```json
{
  "id": "did:example:123",
  "service": [{
    "id": "did:example:123#vcs",
    "type": "VerifiableCredentialService",
    "serviceEndpoint": "https://example.com/vc/"
  }]
}
```

---

## 6. Verification Methods

### 6.1 Verification Method Structure

Each verification method is a map with the following properties:

#### Required Properties:

1. **`id`** (REQUIRED)
   - **Type**: String (DID URL)
   - **Requirement**: **MUST** be a valid DID URL

2. **`type`** (REQUIRED)
   - **Type**: String
   - **Requirement**: **MUST** be a registered verification method type
   - **Examples**: `Ed25519VerificationKey2020`, `JsonWebKey2020`, `EcdsaSecp256k1VerificationKey2019`

3. **`controller`** (REQUIRED)
   - **Type**: String (DID)
   - **Requirement**: **MUST** be a valid DID
   - **Purpose**: Identifies the entity that controls the verification method

#### Public Key Properties (at least one REQUIRED):

4. **`publicKeyJwk`** (OPTIONAL)
   - **Type**: Map (JSON Web Key)
   - **Requirement**: **MUST NOT** contain private key material

5. **`publicKeyMultibase`** (OPTIONAL)
   - **Type**: String (multibase-encoded public key)
   - **Requirement**: **MUST** be a valid multibase encoding

### 6.2 Verification Method Requirements

- A verification method **MUST** include at least one public key property
- A verification method **MUST NOT** contain private key material
- A verification method **MAY** include additional properties specific to the verification method type

### 6.3 Example Verification Methods

**Ed25519 Key**:
```json
{
  "id": "did:example:123#key-1",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:example:123",
  "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
}
```

**JSON Web Key**:
```json
{
  "id": "did:example:123#key-2",
  "type": "JsonWebKey2020",
  "controller": "did:example:123",
  "publicKeyJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
    "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
  }
}
```

---

## 7. Service Endpoints

### 7.1 Service Endpoint Structure

Each service endpoint is a map with the following properties:

#### Required Properties:

1. **`id`** (REQUIRED)
   - **Type**: String (URI)
   - **Requirement**: **MUST** be a valid URI
   - **Note**: Typically a DID URL fragment

2. **`type`** (REQUIRED)
   - **Type**: String or Set of strings
   - **Requirement**: **MUST** be a registered service type
   - **Examples**: `LinkedDomains`, `VerifiableCredentialService`, `MessagingService`

3. **`serviceEndpoint`** (REQUIRED)
   - **Type**: URI, Map, or Set of URIs/Maps
   - **Purpose**: Network address or structured data for the service

### 7.2 Service Endpoint Requirements

- The `id` property **MUST** be unique within the DID document
- The `type` property **SHOULD** be registered in the DID Specification Registries
- The `serviceEndpoint` property **MUST** contain information for interacting with the service

### 7.3 Example Service Endpoints

**Simple Service**:
```json
{
  "id": "did:example:123#linked-domain",
  "type": "LinkedDomains",
  "serviceEndpoint": "https://example.com"
}
```

**Structured Service**:
```json
{
  "id": "did:example:123#messaging",
  "type": "MessagingService",
  "serviceEndpoint": {
    "uri": "https://example.com/messages",
    "accept": ["didcomm/v2"],
    "routingKeys": ["did:example:456#key-1"]
  }
}
```

---

## 8. DID Resolution

### 8.1 Resolution Process

DID resolution is the process of obtaining a DID document from a DID.

**Input**: DID (string)
**Output**: DID document, DID document metadata, DID resolution metadata

### 8.2 Resolution Metadata

Resolution metadata includes:
- `contentType`: MIME type of the DID document representation
- `error`: Error code if resolution failed
- Additional method-specific metadata

### 8.3 DID Document Metadata

DID document metadata includes:
- `created`: Timestamp of DID document creation
- `updated`: Timestamp of last DID document update
- `deactivated`: Boolean indicating if DID is deactivated
- `versionId`: Version identifier
- `nextUpdate`: Expected next update time
- `nextVersionId`: Expected next version identifier

### 8.4 Resolution Requirements

- A DID resolver **MUST** support the DID method it claims to resolve
- A DID resolver **MUST** return conformant DID documents
- A DID resolver **MAY** support resolution options
- A DID resolver **SHOULD** provide metadata

---

## 9. Representations

### 9.1 JSON Representation

- **Content Type**: `application/did+json`
- **Requirements**:
  - **MUST** be valid JSON
  - **MUST** represent the data model accurately
  - **SHOULD** be compact (no unnecessary whitespace)

### 9.2 JSON-LD Representation

- **Content Type**: `application/did+ld+json`
- **Requirements**:
  - **MUST** be valid JSON-LD
  - **MUST** include a `@context` property
  - **MUST** use the DID Core context: `https://www.w3.org/ns/did/v1`

**Example**:
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "authentication": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}
```

---

## 10. DID Methods

### 10.1 DID Method Definition

A DID method is a specification that defines:
1. The method-specific identifier scheme
2. DID document CRUD operations (Create, Read, Update, Deactivate)
3. Security and privacy considerations

### 10.2 DID Method Requirements

A DID method specification **MUST** define:
- The method name
- The method-specific-id format
- DID document operations (create, resolve, update, deactivate)
- Security considerations
- Privacy considerations

### 10.3 Method Registration

- DID methods **SHOULD** be registered in the W3C DID Specification Registries
- Method names **MUST** be unique
- Method names **MUST** consist of lowercase letters and digits

---

## 11. Security Considerations

### 11.1 Cryptographic Security

- Verification methods **MUST** use cryptographically secure algorithms
- Private keys **MUST** be kept secure and **MUST NOT** be included in DID documents
- Key rotation **SHOULD** be supported

### 11.2 Authentication

- DID subjects **MUST** prove control through cryptographic proof
- Authentication mechanisms **SHOULD** use challenge-response protocols
- Replay attacks **SHOULD** be prevented through nonces or timestamps

### 11.3 Authorization

- Controllers **SHOULD** be explicitly defined
- Verification relationships **SHOULD** be appropriately scoped
- Capability invocation and delegation **SHOULD** be carefully managed

### 11.4 Key Management

- Key compromise **MUST** be recoverable through key rotation
- Deactivated DIDs **SHOULD** not be reusable
- Key recovery mechanisms **SHOULD** be considered

---

## 12. Privacy Considerations

### 12.1 Correlation Prevention

- Multiple DIDs **SHOULD** be used to prevent correlation
- DID reuse across contexts **SHOULD** be minimized
- Pairwise DIDs **SHOULD** be used for sensitive interactions

### 12.2 Data Minimization

- DID documents **SHOULD** contain only necessary information
- Personal data **SHOULD NOT** be included in DID documents
- Service endpoints **SHOULD** protect user privacy

### 12.3 Anonymity

- DIDs **MAY** be used pseudonymously
- Biometric data **MUST NOT** be included in DID documents
- Herd privacy techniques **SHOULD** be considered

---

## 13. Conformance

### 13.1 Conformance Criteria

A conformant DID:
- **MUST** conform to the DID Syntax (Section 2)

A conformant DID document:
- **MUST** contain an `id` property matching the DID
- **MUST** conform to the data model (Section 4)
- **MUST** serialize to a valid representation (Section 9)

A conformant DID method:
- **MUST** define all required operations
- **MUST** conform to the DID syntax
- **MUST** produce conformant DID documents

A conformant DID resolver:
- **MUST** implement the resolution algorithm
- **MUST** return conformant DID documents
- **MUST** provide resolution metadata

---

## 14. MUST/SHOULD/MAY Summary

### MUST Requirements (Normative)

1. DID **MUST** conform to syntax: `did:method:method-specific-id`
2. `id` property **MUST** exist in DID document root
3. `id` property **MUST** be a valid DID string
4. Verification method **MUST** have `id`, `type`, `controller`
5. Verification method **MUST NOT** contain private keys
6. Service endpoint **MUST** have `id`, `type`, `serviceEndpoint`
7. DID resolver **MUST** return conformant documents
8. JSON representation **MUST** be valid JSON
9. JSON-LD representation **MUST** include `@context`
10. Controller value **MUST** be a valid DID
11. AlsoKnownAs values **MUST** be valid URIs

### SHOULD Requirements (Recommended)

1. Controller **SHOULD** contain verification methods
2. Service type **SHOULD** be registered
3. DID method **SHOULD** be registered
4. Key rotation **SHOULD** be supported
5. DID documents **SHOULD** be minimal
6. Multiple DIDs **SHOULD** be used to prevent correlation
7. Pairwise DIDs **SHOULD** be used for sensitive interactions
8. Replay attacks **SHOULD** be prevented

### MAY Requirements (Optional)

1. DID **MAY** be case-normalized
2. DID URL **MAY** include query parameters
3. Verification method **MAY** include additional properties
4. DID resolver **MAY** support resolution options
5. DIDs **MAY** be used pseudonymously

---

## 15. Key Concepts for Formalization

### 15.1 Type System

```
DID = String                          // Conforming to DID syntax
DIDDocument = Map<String, Value>
VerificationMethod = Map<String, Value>
ServiceEndpoint = Map<String, Value>
Value = String | Map | List | Set | Number | Boolean | Null
```

### 15.2 Validation Predicates

```
isValidDID(s: String) -> Boolean
  = matches(s, "did:" method-name ":" method-specific-id)

isValidDIDDocument(doc: Map) -> Boolean
  = hasProperty(doc, "id") '
    isValidDID(doc["id"]) '
    validProperties(doc)

isValidVerificationMethod(vm: Map) -> Boolean
  = hasProperty(vm, "id") '
    hasProperty(vm, "type") '
    hasProperty(vm, "controller") '
    hasPublicKey(vm) '
    ¬hasPrivateKey(vm)
```

### 15.3 Core Invariants

1. **DID Uniqueness**: Each DID refers to exactly one DID subject
2. **Document Integrity**: DID document `id` matches the resolved DID
3. **Controller Authority**: Only controllers can modify DID documents
4. **Key Security**: Private keys never appear in DID documents
5. **Verification Method Reference**: Referenced verification methods must exist

---

## 16. Notes for Lean Formalization

### 16.1 Challenges

1. **String Validation**: DID syntax requires regex/parsing (may need axioms)
2. **Extensibility**: DID documents support arbitrary properties (open types)
3. **External Dependencies**: Resolution depends on method implementations
4. **Cryptographic Primitives**: Verification depends on cryptographic operations

### 16.2 Recommended Approach

1. **Core Types**: Define inductive types for DID, DIDDocument, VerificationMethod
2. **Validation Functions**: Define predicates for syntax and structure validation
3. **Well-Formedness**: Prove well-formedness properties
4. **Invariants**: State and prove key invariants
5. **Axioms**: Use axioms for external dependencies (resolution, crypto)

### 16.3 Abstraction Layers

```
Layer 1: Syntax (DID strings, parsing)
Layer 2: Data Model (DID documents, properties)
Layer 3: Operations (resolution, verification)
Layer 4: Security Properties (authentication, authorization)
```

---

## 17. References

- W3C DID Core Specification: https://www.w3.org/TR/did-core/
- DID Specification Registries: https://www.w3.org/TR/did-spec-registries/
- ABNF (RFC 5234): https://tools.ietf.org/html/rfc5234
- JSON (RFC 8259): https://tools.ietf.org/html/rfc8259
- JSON-LD 1.1: https://www.w3.org/TR/json-ld11/
- Multibase: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
