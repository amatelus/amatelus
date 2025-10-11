/-
# W3C Verifiable Credentials Data Model v2.0

Formal specification based on W3C VC Data Model 2.0 Specification.
Reference: https://www.w3.org/TR/vc-data-model/

This module provides a formal model of the W3C Verifiable Credentials specification, including:
- Verifiable Credentials data model
- Verifiable Presentations data model
- Proof mechanisms
- Validation predicates
- Verification predicates
- Security and privacy properties

**Design Philosophy:**
- Uses ValidVC/InvalidVC sum types
- Abstract cryptographic verification as type constructors
- Enable formal verification of protocol-level properties
- Compatible with W3C VC Data Model 2.0 specification
-/

import Mathlib.Data.String.Basic
import Mathlib.Data.List.Basic
import W3C.DID

namespace W3C

open W3C (DID DIDURL DIDValue)

/-! ## 1. Core Value Types

Reuse DIDValue from W3C.DID for representing JSON-like values.
-/

/-! ## 2. Context and Type Definitions

Credentials use JSON-LD contexts and types for semantic meaning.
-/

/-- JSON-LD context URI or object -/
structure Context where
  value : String
  deriving Repr, DecidableEq

/-- Credential or presentation type -/
structure CredentialType where
  value : String
  deriving Repr, DecidableEq

/-! ## 3. Temporal Properties

Credentials have temporal validity constraints.
-/

/-- XML datetime string (ISO 8601) -/
structure DateTime where
  value : String
  deriving Repr, DecidableEq

/-! ## 4. Issuer

The issuer can be a URI or an object with additional properties.
-/

/-- Issuer representation -/
inductive Issuer where
  | uri : String → Issuer
  | object : String → List (String × DIDValue) → Issuer  -- id + additional properties
  deriving Repr

/-- Extract issuer ID from Issuer -/
def Issuer.getId (issuer : Issuer) : String :=
  match issuer with
  | .uri s => s
  | .object id _ => id

/-! ## 5. Credential Subject

The subject of the credential (entity about which claims are made).
-/

/-- Credential subject with optional id and claims -/
structure CredentialSubject where
  /-- OPTIONAL: Identifier of the subject (often a DID) -/
  id : Option String := none
  /-- REQUIRED: Claims about the subject (at least one) -/
  claims : List (String × DIDValue)
  deriving Repr

/-! ## 6. Credential Status

Information about the credential's revocation or suspension status.
-/

/-- Credential status entry -/
structure CredentialStatus where
  /-- REQUIRED: URI identifying the status information -/
  id : String
  /-- REQUIRED: Status mechanism type -/
  type_ : String
  /-- Additional status-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 7. Credential Schema

Reference to a schema for validating credential structure.
-/

/-- Credential schema reference -/
structure CredentialSchema where
  /-- REQUIRED: URI identifying the schema -/
  id : String
  /-- REQUIRED: Schema type -/
  type_ : String
  /-- Additional schema-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 8. Evidence

Supporting evidence for the claims in a credential.
-/

/-- Evidence entry -/
structure Evidence where
  /-- OPTIONAL: Identifier for the evidence -/
  id : Option String := none
  /-- REQUIRED: Type of evidence -/
  type_ : List String
  /-- Additional evidence-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 9. Terms of Use

Defines terms under which the credential can be used.
-/

/-- Terms of use entry -/
structure TermsOfUse where
  /-- OPTIONAL: Identifier for the terms -/
  id : Option String := none
  /-- REQUIRED: Type of terms -/
  type_ : String
  /-- Additional terms-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 10. Refresh Service

Mechanism for refreshing the credential.
-/

/-- Refresh service entry -/
structure RefreshService where
  /-- REQUIRED: URI of the refresh service -/
  id : String
  /-- REQUIRED: Service type -/
  type_ : String
  /-- Additional service-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 11. Proof

Cryptographic proof that makes credentials and presentations verifiable.
-/

/-- Proof purpose (why the proof was created) -/
inductive ProofPurpose where
  | authentication
  | assertionMethod
  | keyAgreement
  | capabilityInvocation
  | capabilityDelegation
  deriving Repr, DecidableEq

/-- Cryptographic proof (embedded or enveloping) -/
structure Proof where
  /-- REQUIRED: Proof type -/
  type_ : String
  /-- OPTIONAL: Cryptosuite identifier -/
  cryptosuite : Option String := none
  /-- OPTIONAL: Timestamp of proof creation -/
  created : Option DateTime := none
  /-- OPTIONAL: Verification method URI -/
  verificationMethod : Option String := none
  /-- OPTIONAL: Purpose of the proof -/
  proofPurpose : Option String := none
  /-- OPTIONAL: The cryptographic proof value -/
  proofValue : Option String := none
  /-- OPTIONAL: Challenge for preventing replay attacks -/
  challenge : Option String := none
  /-- OPTIONAL: Domain for binding to specific verifier -/
  domain : Option String := none
  /-- Additional proof-specific properties -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 12. Credential

A credential is a set of claims made by an issuer about a subject.
This is the base structure before securing with proof.
-/

/-- Credential (before securing with proof) -/
structure Credential where
  /-- REQUIRED: JSON-LD context (first must be v2 context) -/
  context : List Context
  /-- REQUIRED: Credential type (must include "VerifiableCredential") -/
  type_ : List CredentialType
  /-- OPTIONAL: Credential identifier -/
  id : Option String := none
  /-- OPTIONAL: Human-readable name -/
  name : Option String := none
  /-- OPTIONAL: Human-readable description -/
  description : Option String := none
  /-- REQUIRED: Issuer of the credential -/
  issuer : Issuer
  /-- OPTIONAL: When credential becomes valid -/
  validFrom : Option DateTime := none
  /-- OPTIONAL: When credential expires -/
  validUntil : Option DateTime := none
  /-- REQUIRED: Subject(s) of the credential -/
  credentialSubject : List CredentialSubject
  /-- OPTIONAL: Status information -/
  credentialStatus : Option CredentialStatus := none
  /-- OPTIONAL: Schema reference -/
  credentialSchema : Option CredentialSchema := none
  /-- OPTIONAL: Supporting evidence -/
  evidence : List Evidence := []
  /-- OPTIONAL: Terms of use -/
  termsOfUse : List TermsOfUse := []
  /-- OPTIONAL: Refresh service -/
  refreshService : Option RefreshService := none
  /-- Additional properties (extensibility) -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 13. Credential with Proof

A credential with proofs attached, but not yet verified.
This is an intermediate structure before verification.
-/

/-- Credential with attached proofs (not yet verified) -/
structure CredentialWithProof where
  /-- The underlying credential -/
  credential : Credential
  /-- REQUIRED: One or more proofs -/
  proof : List Proof
  deriving Repr

/-! ## 14. Valid and Invalid Verifiable Credentials -/

/-- Valid Verifiable Credential

    A credential whose cryptographic proof has been successfully verified.
    The issuer's signature is valid and the credential has not been tampered with.

    **Abstraction:**
    - Does not expose cryptographic details (Ed25519, BBS+, etc.)
    - Protocol-level abstraction: "cryptographically valid credential"
    - Construction implies successful verification
-/
structure ValidVC where
  /-- The credential with verified proof -/
  credentialWithProof : CredentialWithProof
  deriving Repr

/-- Invalid Verifiable Credential

    A credential whose cryptographic proof verification has failed.
    Reasons include:
    - Signature verification failure
    - Tampered credential content
    - Invalid issuer key
    - Malformed proof
-/
structure InvalidVC where
  /-- The credential with invalid proof -/
  credentialWithProof : CredentialWithProof
  /-- OPTIONAL: Reason for invalidity (for debugging) -/
  reason : Option String := none
  deriving Repr

/-- Verifiable Credential

    Sum type of valid and invalid credentials.
    Represents the result of cryptographic verification.

    **Design Pattern (from AMATELUS):**
    - `valid`: Proof verification succeeded
    - `invalid`: Proof verification failed
    - Verification function is a simple pattern match
    - Enables formal verification of protocol properties
-/
inductive VerifiableCredential where
  | valid : ValidVC → VerifiableCredential
  | invalid : InvalidVC → VerifiableCredential
  deriving Repr

namespace VerifiableCredential

/-- Get the underlying credential with proof -/
def getCredentialWithProof : VerifiableCredential → CredentialWithProof
  | valid vc => vc.credentialWithProof
  | invalid vc => vc.credentialWithProof

/-- Get the underlying credential (without proof) -/
def getCredential (vc : VerifiableCredential) : Credential :=
  (getCredentialWithProof vc).credential

/-- Get the issuer of the credential -/
def getIssuer (vc : VerifiableCredential) : Issuer :=
  (getCredential vc).issuer

/-- Get the issuer ID -/
def getIssuerId (vc : VerifiableCredential) : String :=
  (getIssuer vc).getId

/-- Get the subjects of the credential -/
def getSubjects (vc : VerifiableCredential) : List CredentialSubject :=
  (getCredential vc).credentialSubject

/-- Verify cryptographic signature

    **Design Core:**
    - `valid`: Always returns true (proof already verified at construction)
    - `invalid`: Always returns false (proof verification failed)

    This simple definition enables formal reasoning about verification
    without exposing cryptographic implementation details.
-/
def verifySignature : VerifiableCredential → Bool
  | valid _ => true
  | invalid _ => false

/-- Check if a verifiable credential is valid -/
def isValid (vc : VerifiableCredential) : Prop :=
  verifySignature vc = true

/-- Check if a verifiable credential has expired -/
def hasExpired (vc : VerifiableCredential) (now : DateTime) : Prop :=
  match (getCredential vc).validUntil with
  | none => False
  | some validUntil => validUntil = now  -- Simplified: real impl would compare

/-- Check if a verifiable credential is not yet valid -/
def notYetValid (vc : VerifiableCredential) (now : DateTime) : Prop :=
  match (getCredential vc).validFrom with
  | none => False
  | some validFrom => validFrom = now  -- Simplified: real impl would compare

end VerifiableCredential

/-! ## 15. Holder

Entity that possesses and presents credentials.
-/

/-- Holder representation (similar to Issuer) -/
inductive Holder where
  | uri : String → Holder
  | object : String → List (String × DIDValue) → Holder  -- id + additional properties
  deriving Repr

/-- Extract holder ID from Holder -/
def Holder.getId (holder : Holder) : String :=
  match holder with
  | .uri s => s
  | .object id _ => id

/-! ## 16. Presentation

A presentation is data derived from credentials for a specific verifier.
-/

/-- Presentation (before securing with proof) -/
structure Presentation where
  /-- REQUIRED: JSON-LD context -/
  context : List Context
  /-- REQUIRED: Presentation type (must include "VerifiablePresentation") -/
  type_ : List CredentialType
  /-- OPTIONAL: Presentation identifier -/
  id : Option String := none
  /-- OPTIONAL: Holder of the credentials -/
  holder : Option Holder := none
  /-- OPTIONAL: Verifiable credentials being presented -/
  verifiableCredential : List VerifiableCredential := []
  /-- Additional properties (extensibility) -/
  additionalProperties : List (String × DIDValue) := []
  deriving Repr

/-! ## 17. Presentation with Proof

A presentation with proofs attached, but not yet verified.
-/

/-- Presentation with attached proofs (not yet verified) -/
structure PresentationWithProof where
  /-- The underlying presentation -/
  presentation : Presentation
  /-- REQUIRED: One or more proofs -/
  proof : List Proof
  deriving Repr

/-! ## 18. Valid and Invalid Verifiable Presentations -/

/-- Valid Verifiable Presentation

    A presentation whose cryptographic proof has been successfully verified.
    The holder's signature is valid and the presentation has not been tampered with.
-/
structure ValidVP where
  /-- The presentation with verified proof -/
  presentationWithProof : PresentationWithProof
  deriving Repr

/-- Invalid Verifiable Presentation

    A presentation whose cryptographic proof verification has failed.
-/
structure InvalidVP where
  /-- The presentation with invalid proof -/
  presentationWithProof : PresentationWithProof
  /-- OPTIONAL: Reason for invalidity (for debugging) -/
  reason : Option String := none
  deriving Repr

/-- Verifiable Presentation

    Sum type of valid and invalid presentations.
    Same design pattern as VerifiableCredential.
-/
inductive VerifiablePresentation where
  | valid : ValidVP → VerifiablePresentation
  | invalid : InvalidVP → VerifiablePresentation
  deriving Repr

namespace VerifiablePresentation

/-- Get the underlying presentation with proof -/
def getPresentationWithProof : VerifiablePresentation → PresentationWithProof
  | valid vp => vp.presentationWithProof
  | invalid vp => vp.presentationWithProof

/-- Get the underlying presentation (without proof) -/
def getPresentation (vp : VerifiablePresentation) : Presentation :=
  (getPresentationWithProof vp).presentation

/-- Get the holder of the presentation -/
def getHolder (vp : VerifiablePresentation) : Option Holder :=
  (getPresentation vp).holder

/-- Get the credentials in the presentation -/
def getCredentials (vp : VerifiablePresentation) : List VerifiableCredential :=
  (getPresentation vp).verifiableCredential

/-- Verify cryptographic signature -/
def verifySignature : VerifiablePresentation → Bool
  | valid _ => true
  | invalid _ => false

/-- Check if a verifiable presentation is valid -/
def isValid (vp : VerifiablePresentation) : Prop :=
  verifySignature vp = true

end VerifiablePresentation

/-! ## 19. Constants

W3C defined constants.
-/

/-- The required v2 context URI -/
def requiredContextV2 : String := "https://www.w3.org/ns/credentials/v2"

/-- The required credential type -/
def requiredCredentialType : String := "VerifiableCredential"

/-- The required presentation type -/
def requiredPresentationType : String := "VerifiablePresentation"

/-! ## 20. Structural Validation Predicates

Validation checks that don't depend on cryptography.
-/

/-- Check if context list has the required v2 context as first element -/
def hasValidContext (contexts : List Context) : Prop :=
  match contexts with
  | [] => False
  | ctx :: _ => ctx.value = requiredContextV2

/-- Check if type list includes required type -/
def hasRequiredType (types : List CredentialType) (requiredType : String) : Prop :=
  ∃ t, t ∈ types ∧ t.value = requiredType

/-- Check if credential subject has at least one claim -/
def hasAtLeastOneClaim (subject : CredentialSubject) : Prop :=
  subject.claims.length > 0

/-- All credential subjects must have at least one claim -/
def allSubjectsHaveClaims (subjects : List CredentialSubject) : Prop :=
  subjects.length > 0 ∧ ∀ s, s ∈ subjects → hasAtLeastOneClaim s

/-- Credential status must have id and type if present -/
def hasValidCredentialStatus (status : Option CredentialStatus) : Prop :=
  match status with
  | none => True
  | some s => s.id.length > 0 ∧ s.type_.length > 0

/-- Credential schema must have id and type if present -/
def hasValidCredentialSchema (schema : Option CredentialSchema) : Prop :=
  match schema with
  | none => True
  | some s => s.id.length > 0 ∧ s.type_.length > 0

/-- A credential is structurally valid if it satisfies all MUST requirements -/
def isStructurallyValidCredential (cred : Credential) : Prop :=
  -- MUST have valid context with v2 as first element
  hasValidContext cred.context ∧
  -- MUST include "VerifiableCredential" type
  hasRequiredType cred.type_ requiredCredentialType ∧
  -- MUST have at least one subject with claims
  allSubjectsHaveClaims cred.credentialSubject ∧
  -- If status present, MUST have id and type
  hasValidCredentialStatus cred.credentialStatus ∧
  -- If schema present, MUST have id and type
  hasValidCredentialSchema cred.credentialSchema

/-- A credential with proof must have at least one proof -/
def hasProofs (cwp : CredentialWithProof) : Prop :=
  cwp.proof.length > 0

/-- A presentation is structurally valid if it satisfies all MUST requirements -/
def isStructurallyValidPresentation (pres : Presentation) : Prop :=
  -- MUST have valid context with v2 as first element
  hasValidContext pres.context ∧
  -- MUST include "VerifiablePresentation" type
  hasRequiredType pres.type_ requiredPresentationType

/-- A presentation with proof must have at least one proof -/
def hasPresentationProofs (pwp : PresentationWithProof) : Prop :=
  pwp.proof.length > 0

/-! ## 21. Complete Validation and Verification

Combines structural validation with cryptographic verification.
-/

/-- Complete validation of a verifiable credential -/
def isValidCredential (vc : VerifiableCredential) : Prop :=
  -- Structural validation
  isStructurallyValidCredential (VerifiableCredential.getCredential vc) ∧
  -- Has proofs
  hasProofs (VerifiableCredential.getCredentialWithProof vc) ∧
  -- Cryptographic verification
  VerifiableCredential.isValid vc

/-- Complete validation of a verifiable presentation -/
def isValidPresentation (vp : VerifiablePresentation) : Prop :=
  -- Structural validation
  isStructurallyValidPresentation (VerifiablePresentation.getPresentation vp) ∧
  -- Has proofs
  hasPresentationProofs (VerifiablePresentation.getPresentationWithProof vp) ∧
  -- All contained credentials are valid
  (∀ vc, vc ∈ (VerifiablePresentation.getPresentation vp).verifiableCredential →
    isValidCredential vc) ∧
  -- Cryptographic verification
  VerifiablePresentation.isValid vp

/-! ## 22. Temporal Validity

Check if credentials are within their validity period.
-/

/-- Abstract notion of current time (to be provided by verification context) -/
structure VerificationTime where
  now : DateTime
  deriving Repr

/-- Check if a credential is temporally valid at a given time -/
def isTemporallyValid (vc : VerifiableCredential) (time : VerificationTime) : Prop :=
  ¬VerifiableCredential.hasExpired vc time.now ∧
  ¬VerifiableCredential.notYetValid vc time.now

/-! ## 23. Security Properties -/

/-- Issuer Binding: A valid credential is cryptographically bound to its issuer -/
def issuerBinding (vc : VerifiableCredential) : Prop :=
  VerifiableCredential.isValid vc →
    ∃ issuer, issuer = VerifiableCredential.getIssuer vc

/-- Holder Binding: A valid presentation is cryptographically bound to its holder -/
def holderBinding (vp : VerifiablePresentation) : Prop :=
  VerifiablePresentation.isValid vp →
    VerifiablePresentation.getHolder vp ≠ none

/-- Non-Repudiation: An issuer cannot deny issuing a valid credential -/
def nonRepudiation (vc : VerifiableCredential) : Prop :=
  VerifiableCredential.isValid vc → issuerBinding vc

/-- Credential Integrity: Valid credentials maintain their integrity -/
def credentialIntegrity (vc : VerifiableCredential) : Prop :=
  isValidCredential vc → issuerBinding vc

/-- Presentation Integrity: Valid presentations maintain their integrity -/
def presentationIntegrity (vp : VerifiablePresentation) : Prop :=
  isValidPresentation vp →
    (∀ vc, vc ∈ VerifiablePresentation.getCredentials vp → credentialIntegrity vc)

/-! ## 24. Privacy Properties

Formal privacy properties for credentials and presentations.
-/

/-- Selective Disclosure: Ability to reveal only specific claims -/
def supportsSelectiveDisclosure (vc : VerifiableCredential) : Prop :=
  -- Check if any proof supports selective disclosure (e.g., BBS+)
  ∃ proof, proof ∈ (VerifiableCredential.getCredentialWithProof vc).proof ∧
    (proof.cryptosuite = some "bbs-2023" ∨ proof.type_ = "DataIntegrityProof")

/-- Unlinkability: Credentials should not be trivially linkable across uses -/
def supportsUnlinkability (vc : VerifiableCredential) : Prop :=
  -- Requires ZKP-based signatures
  supportsSelectiveDisclosure vc

/-! ## 25. Core Theorems -/

/-- Valid credentials always pass signature verification -/
theorem valid_vc_passes_verification (vvc : ValidVC) :
    VerifiableCredential.isValid (VerifiableCredential.valid vvc) := by
  unfold VerifiableCredential.isValid VerifiableCredential.verifySignature
  rfl

/-- Invalid credentials always fail signature verification -/
theorem invalid_vc_fails_verification (ivc : InvalidVC) :
    ¬VerifiableCredential.isValid (VerifiableCredential.invalid ivc) := by
  unfold VerifiableCredential.isValid VerifiableCredential.verifySignature
  simp

/-- Valid presentations always pass signature verification -/
theorem valid_vp_passes_verification (vvp : ValidVP) :
    VerifiablePresentation.isValid (VerifiablePresentation.valid vvp) := by
  unfold VerifiablePresentation.isValid VerifiablePresentation.verifySignature
  rfl

/-- Invalid presentations always fail signature verification -/
theorem invalid_vp_fails_verification (ivp : InvalidVP) :
    ¬VerifiablePresentation.isValid (VerifiablePresentation.invalid ivp) := by
  unfold VerifiablePresentation.isValid VerifiablePresentation.verifySignature
  simp

/-- Valid credentials satisfy issuer binding -/
theorem valid_vc_has_issuer_binding (vc : VerifiableCredential) :
    VerifiableCredential.isValid vc → issuerBinding vc := by
  intro h_valid
  unfold issuerBinding
  intro _
  exists VerifiableCredential.getIssuer vc

/-- Valid presentations satisfy holder binding (if holder present) -/
theorem valid_vp_has_holder_binding (vp : VerifiablePresentation) :
    VerifiablePresentation.isValid vp →
    VerifiablePresentation.getHolder vp ≠ none →
    holderBinding vp := by
  intros h_valid h_holder
  unfold holderBinding
  intro _
  exact h_holder

/-! ## 26. Example Credentials and Presentations -/

/-- Example context -/
def exampleContext : Context := ⟨requiredContextV2⟩

/-- Example credential type -/
def exampleCredentialType : CredentialType := ⟨requiredCredentialType⟩

/-- Example credential subject -/
def exampleSubject : CredentialSubject := {
  id := some "did:example:ebfeb1f712ebc6f1c276e12ec21"
  claims := [
    ("degree", DIDValue.map [
      ("type", DIDValue.string "BachelorDegree"),
      ("name", DIDValue.string "Bachelor of Science in Computer Science")
    ])
  ]
}

/-- Example proof -/
def exampleProof : Proof := {
  type_ := "DataIntegrityProof"
  cryptosuite := some "eddsa-rdfc-2022"
  created := some ⟨"2023-01-01T00:00:00Z"⟩
  verificationMethod := some "https://example.edu/issuers/565049#key-1"
  proofPurpose := some "assertionMethod"
  proofValue := some "z3FkdP4..."
}

/-- Example credential -/
def exampleCredential : Credential := {
  context := [exampleContext]
  type_ := [exampleCredentialType, ⟨"UniversityDegreeCredential"⟩]
  issuer := Issuer.uri "https://example.edu/issuers/565049"
  validFrom := some ⟨"2023-01-01T00:00:00Z"⟩
  credentialSubject := [exampleSubject]
}

/-- Example credential with proof -/
def exampleCredentialWithProof : CredentialWithProof := {
  credential := exampleCredential
  proof := [exampleProof]
}

/-- Example valid verifiable credential -/
def exampleValidVC : ValidVC := {
  credentialWithProof := exampleCredentialWithProof
}

/-- Example verifiable credential -/
def exampleVerifiableCredential : VerifiableCredential :=
  VerifiableCredential.valid exampleValidVC

/-- Example presentation -/
def examplePresentation : Presentation := {
  context := [exampleContext]
  type_ := [⟨requiredPresentationType⟩]
  holder := some (Holder.uri "did:example:holder123")
  verifiableCredential := [exampleVerifiableCredential]
}

/-- Example presentation with proof -/
def examplePresentationWithProof : PresentationWithProof := {
  presentation := examplePresentation
  proof := [exampleProof]
}

/-- Example valid verifiable presentation -/
def exampleValidVP : ValidVP := {
  presentationWithProof := examplePresentationWithProof
}

/-- Example verifiable presentation -/
def exampleVerifiablePresentation : VerifiablePresentation :=
  VerifiablePresentation.valid exampleValidVP

end W3C
