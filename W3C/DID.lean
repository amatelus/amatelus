/-
# W3C Decentralized Identifiers (DIDs) v1.0

Formal specification based on W3C DID Core Specification.
Reference: https://www.w3.org/TR/did-core/

This module provides a formal model of the W3C DID specification, including:
- DID syntax and structure
- DID Document data model
- Verification methods
- Service endpoints
- Validation predicates
- Security properties
-/

import Mathlib.Data.String.Basic
import Mathlib.Data.List.Basic

namespace W3C

/-! ## 1. Core Data Types

The DID document data model supports multiple data types.
We model this as an inductive type representing JSON-like values.
-/

/-- Core value types supported in DID documents -/
inductive DIDValue where
  | string : String → DIDValue
  | int : Int → DIDValue
  | double : Float → DIDValue
  | bool : Bool → DIDValue
  | null : DIDValue
  | list : List DIDValue → DIDValue
  | map : List (String × DIDValue) → DIDValue
  deriving Repr

/-! ## 2. DID Syntax

DID Syntax ABNF:
```
did                = "did:" method-name ":" method-specific-id
method-name        = 1*method-char
method-char        = %x61-7A / DIGIT  ; lowercase letters (a-z) and digits (0-9)
method-specific-id = *( *idchar ":" ) 1*idchar
idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
pct-encoded        = "%" HEXDIG HEXDIG
```
-/

/-- A DID (Decentralized Identifier) string.
    Must conform to the syntax: did:method:method-specific-id -/
structure DID where
  /-- The complete DID string -/
  value : String
  deriving Repr, DecidableEq

/-- Method name component of a DID -/
structure MethodName where
  value : String
  deriving Repr, DecidableEq

/-- Method-specific identifier component -/
structure MethodSpecificId where
  value : String
  deriving Repr, DecidableEq

/-- DID URL extends DID with optional path, query, and fragment -/
structure DIDURL where
  did : DID
  path : Option String := none
  query : Option String := none
  fragment : Option String := none
  deriving Repr, DecidableEq

/-! ## 3. Verification Methods

A verification method expresses verification material and metadata about it.
-/

/-- Verification method type identifier (e.g., Ed25519VerificationKey2020) -/
structure VerificationMethodType where
  value : String
  deriving Repr, DecidableEq

/-- Public key representation in JWK format -/
structure PublicKeyJwk where
  /-- Key type (e.g., "EC", "RSA", "OKP") -/
  kty : String
  /-- Additional JWK properties -/
  properties : List (String × DIDValue)
  deriving Repr

/-- A verification method defines cryptographic material for verification -/
structure VerificationMethod where
  /-- REQUIRED: Identifier for the verification method (DID URL) -/
  id : DIDURL
  /-- REQUIRED: Type of verification method -/
  type_ : VerificationMethodType
  /-- REQUIRED: DID of the controller -/
  controller : DID
  /-- OPTIONAL: Public key in JWK format -/
  publicKeyJwk : Option PublicKeyJwk := none
  /-- OPTIONAL: Public key in multibase format -/
  publicKeyMultibase : Option String := none
  /-- Additional properties specific to the verification method type -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-- Verification relationship reference (either embedded or referenced) -/
inductive VerificationRelationship where
  | embedded : VerificationMethod → VerificationRelationship
  | reference : DIDURL → VerificationRelationship
  deriving Repr

/-! ## 4. Service Endpoints

Service endpoints express ways to interact with the DID subject.
-/

/-- Service type identifier -/
structure ServiceType where
  value : String
  deriving Repr, DecidableEq

/-- Service endpoint value (can be URI, map, or set) -/
inductive ServiceEndpointValue where
  | uri : String → ServiceEndpointValue
  | map : List (String × DIDValue) → ServiceEndpointValue
  | set : List ServiceEndpointValue → ServiceEndpointValue
  deriving Repr

/-- A service endpoint defines how to interact with the DID subject -/
structure ServiceEndpoint where
  /-- REQUIRED: Identifier for the service endpoint -/
  id : String
  /-- REQUIRED: Type of service -/
  type_ : List ServiceType
  /-- REQUIRED: Service endpoint URI or structured data -/
  serviceEndpoint : ServiceEndpointValue
  /-- Additional service-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 5. DID Document

A DID document contains information about a DID subject.
-/

/-- A DID document is the core data structure -/
structure DIDDocument where
  /-- REQUIRED: The DID that this document describes -/
  id : DID

  /-- OPTIONAL: Alternative identifiers for the DID subject -/
  alsoKnownAs : List String := []

  /-- OPTIONAL: Controllers authorized to make changes -/
  controller : List DID := []

  /-- OPTIONAL: Verification methods for the DID subject -/
  verificationMethod : List VerificationMethod := []

  /-- OPTIONAL: Authentication verification relationships -/
  authentication : List VerificationRelationship := []

  /-- OPTIONAL: Assertion method verification relationships -/
  assertionMethod : List VerificationRelationship := []

  /-- OPTIONAL: Key agreement verification relationships -/
  keyAgreement : List VerificationRelationship := []

  /-- OPTIONAL: Capability invocation verification relationships -/
  capabilityInvocation : List VerificationRelationship := []

  /-- OPTIONAL: Capability delegation verification relationships -/
  capabilityDelegation : List VerificationRelationship := []

  /-- OPTIONAL: Service endpoints -/
  service : List ServiceEndpoint := []

  /-- Additional properties (extensibility) -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 6. DID Resolution

DID resolution is the process of obtaining a DID document from a DID.
-/

/-- DID resolution metadata -/
structure ResolutionMetadata where
  /-- MIME type of the DID document representation -/
  contentType : Option String := none
  /-- Error code if resolution failed -/
  error : Option String := none
  /-- Additional metadata -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-- DID document metadata -/
structure DocumentMetadata where
  /-- Timestamp of DID document creation -/
  created : Option String := none
  /-- Timestamp of last update -/
  updated : Option String := none
  /-- Whether the DID is deactivated -/
  deactivated : Bool := false
  /-- Version identifier -/
  versionId : Option String := none
  /-- Expected next update time -/
  nextUpdate : Option String := none
  /-- Expected next version identifier -/
  nextVersionId : Option String := none
  /-- Additional metadata -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-- Result of DID resolution -/
structure ResolutionResult where
  /-- The resolved DID document (if successful) -/
  document : Option DIDDocument
  /-- Metadata about the resolution process -/
  resolutionMetadata : ResolutionMetadata
  /-- Metadata about the DID document -/
  documentMetadata : DocumentMetadata
  deriving Repr

/-! ## 7. Validation Predicates

Predicates for validating DID syntax and structure.
-/

/-- Check if a character is a valid method character (lowercase letter or digit) -/
def isMethodChar (c : Char) : Bool :=
  ('a' ≤ c ∧ c ≤ 'z') ∨ ('0' ≤ c ∧ c ≤ '9')

/-- Check if a character is a valid idchar -/
def isIdChar (c : Char) : Bool :=
  ('A' ≤ c ∧ c ≤ 'Z') ∨ ('a' ≤ c ∧ c ≤ 'z') ∨ ('0' ≤ c ∧ c ≤ '9') ∨
  c = '.' ∨ c = '-' ∨ c = '_' ∨ c = '%'

/-- Check if a string is a valid method name -/
def isValidMethodName (s : String) : Bool :=
  s.length > 0 ∧ s.all isMethodChar

/-- Check if a string is a valid method-specific-id -/
def isValidMethodSpecificId (s : String) : Bool :=
  s.length > 0 ∧ s.all isIdChar

/-- Basic syntax validation for DID strings.
    A valid DID must match: did:method:method-specific-id -/
def isValidDIDSyntax (did : DID) : Prop :=
  ∃ (method : String) (id : String),
    did.value = "did:" ++ method ++ ":" ++ id ∧
    isValidMethodName method = true ∧
    isValidMethodSpecificId id = true

/-- A verification method must have at least one public key representation.
    Note: The W3C DID spec requires that verification methods MUST NOT contain
    private key material. This property is structurally guaranteed by the
    VerificationMethod type, which only includes public key fields. -/
def hasPublicKey (vm : VerificationMethod) : Prop :=
  vm.publicKeyJwk.isSome ∨ vm.publicKeyMultibase.isSome

/-- Check if a verification relationship reference exists in the document -/
def verificationRelationshipExists (doc : DIDDocument) (vr : VerificationRelationship) : Prop :=
  match vr with
  | .embedded _ => True  -- Embedded methods are always valid
  | .reference url => ∃ vm, vm ∈ doc.verificationMethod ∧ vm.id = url

/-- All verification relationships must be valid -/
def allVerificationRelationshipsValid (doc : DIDDocument) : Prop :=
  (∀ vr, vr ∈ doc.authentication → verificationRelationshipExists doc vr) ∧
  (∀ vr, vr ∈ doc.assertionMethod → verificationRelationshipExists doc vr) ∧
  (∀ vr, vr ∈ doc.keyAgreement → verificationRelationshipExists doc vr) ∧
  (∀ vr, vr ∈ doc.capabilityInvocation → verificationRelationshipExists doc vr) ∧
  (∀ vr, vr ∈ doc.capabilityDelegation → verificationRelationshipExists doc vr)

/-- A DID document is valid if it satisfies all requirements -/
def isValidDIDDocument (doc : DIDDocument) : Prop :=
  -- The id must be a valid DID
  isValidDIDSyntax doc.id ∧
  -- All verification methods must have at least one public key representation
  (∀ vm, vm ∈ doc.verificationMethod → hasPublicKey vm) ∧
  -- All verification relationships must reference existing methods
  allVerificationRelationshipsValid doc ∧
  -- All controllers must be valid DIDs
  (∀ controller, controller ∈ doc.controller → isValidDIDSyntax controller) ∧
  -- Service endpoint IDs must be unique
  (∀ s1 s2, s1 ∈ doc.service → s2 ∈ doc.service → s1.id = s2.id → s1 = s2)

/-! ## 8. Core Invariants

Key properties that must hold for DID documents.
-/

/-- Document Integrity: The DID document's id matches the resolved DID -/
def documentIntegrity (did : DID) (doc : DIDDocument) : Prop :=
  doc.id = did

/-- Controller Authority: A controller must be a valid DID -/
def controllerAuthority (doc : DIDDocument) : Prop :=
  ∀ controller, controller ∈ doc.controller → isValidDIDSyntax controller

/-- Verification Method Reference Integrity -/
def verificationMethodReferenceIntegrity (doc : DIDDocument) : Prop :=
  allVerificationRelationshipsValid doc

/-! ## 9. Security Properties

Formal properties related to security and privacy.
-/

/-- A DID can be authenticated if it has authentication verification methods -/
def canAuthenticate (doc : DIDDocument) : Prop :=
  doc.authentication.length > 0

/-- A DID can issue credentials if it has assertion methods -/
def canIssueCredentials (doc : DIDDocument) : Prop :=
  doc.assertionMethod.length > 0

/-- A DID can establish secure communication if it has key agreement methods -/
def canEstablishSecureComm (doc : DIDDocument) : Prop :=
  doc.keyAgreement.length > 0

/-- A DID can invoke capabilities if it has capability invocation methods -/
def canInvokeCapabilities (doc : DIDDocument) : Prop :=
  doc.capabilityInvocation.length > 0

/-- A DID can delegate capabilities if it has capability delegation methods -/
def canDelegateCapabilities (doc : DIDDocument) : Prop :=
  doc.capabilityDelegation.length > 0

/-! ## 10. Well-formedness Theorems -/

/-- If a DID document is valid, it maintains document integrity -/
theorem valid_document_has_integrity (did : DID) (doc : DIDDocument) :
    isValidDIDDocument doc → documentIntegrity did doc → doc.id = did := by
  intros _ h
  exact h

/-- Valid documents satisfy controller authority -/
theorem valid_document_has_controller_authority (doc : DIDDocument) :
    isValidDIDDocument doc → controllerAuthority doc := by
  intro ⟨_, _, _, h, _⟩
  exact h

/-- Valid documents have verification method reference integrity -/
theorem valid_document_has_vm_integrity (doc : DIDDocument) :
    isValidDIDDocument doc → verificationMethodReferenceIntegrity doc := by
  intro ⟨_, _, h, _⟩
  exact h

/-! ## 11. Example DIDs and Documents -/

/-- Example DID -/
def exampleDID : DID := ⟨"did:example:123456789abcdefghi"⟩

/-- Example verification method -/
def exampleVerificationMethod : VerificationMethod := {
  id := { did := exampleDID, fragment := some "keys-1" }
  type_ := ⟨"Ed25519VerificationKey2020"⟩
  controller := exampleDID
  publicKeyMultibase := some "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
}

/-- Example service endpoint -/
def exampleServiceEndpoint : ServiceEndpoint := {
  id := "did:example:123456789abcdefghi#vcs"
  type_ := [⟨"VerifiableCredentialService"⟩]
  serviceEndpoint := .uri "https://example.com/vc/"
}

/-- Example minimal DID document -/
def exampleMinimalDocument : DIDDocument := {
  id := exampleDID
}

/-- Example full DID document -/
def exampleFullDocument : DIDDocument := {
  id := exampleDID
  verificationMethod := [exampleVerificationMethod]
  authentication := [.reference { did := exampleDID, fragment := some "keys-1" }]
  service := [exampleServiceEndpoint]
}

end W3C
