/-
# AMATELUSプロトコルの基本定義

このファイルは、AMATELUSプロトコルの基本的な型と定義を含みます。
-/

-- ## 基本型定義

/-- ハッシュ値を表す型 -/
structure Hash where
  value : ByteArray

/-- 公開鍵を表す型 -/
structure PublicKey where
  bytes : ByteArray

/-- 秘密鍵を表す型 -/
structure SecretKey where
  bytes : ByteArray

/-- デジタル署名を表す型 -/
structure Signature where
  bytes : ByteArray

/-- サービスエンドポイントを表す型 -/
structure ServiceEndpoint where
  url : String
  deriving Repr, DecidableEq

/-- メタデータを表す型 -/
structure Metadata where
  data : String
  deriving Repr, DecidableEq

-- ## Definition 2.1: DID and DID Document

/-- DIDドキュメントを表す構造体 -/
structure DIDDocument where
  publicKey : PublicKey
  service : ServiceEndpoint
  metadata : Metadata

/-- DID (Decentralized Identifier) を表す型
    DID := did:amatelus:H(DIDDoc) -/
structure DID where
  hash : Hash

namespace DID

/-- DIDドキュメントからDIDを生成する（暗号ハッシュ関数は公理化） -/
axiom fromDocument : DIDDocument → DID

/-- DIDがDIDドキュメントから正しく生成されたかを検証 -/
def isValid (did : DID) (doc : DIDDocument) : Prop :=
  did = fromDocument doc

end DID

-- ## Definition 2.2: Verifiable Credential

/-- VCのコンテキストを表す型 -/
structure Context where
  value : String
  deriving Repr, DecidableEq

/-- VCのタイプを表す型 -/
structure VCType where
  value : String
  deriving Repr, DecidableEq

/-- クレーム（主張）を表す型 -/
structure Claims where
  data : String  -- 実際には構造化データ
  deriving Repr, DecidableEq

/-- 失効情報を表す型 -/
structure RevocationInfo where
  statusListUrl : Option String
  deriving Repr, DecidableEq

/-- 検証可能資格情報 (Verifiable Credential) を表す構造体 -/
structure VerifiableCredential where
  context : Context
  type : VCType
  issuer : DID
  subject : DID
  claims : Claims
  signature : Signature
  credentialStatus : RevocationInfo

namespace VerifiableCredential

/-- VCが有効かどうかを表す述語 -/
def isValid (_vc : VerifiableCredential) : Prop :=
  -- 署名検証は公理化
  True  -- 実際の実装では署名検証が必要

end VerifiableCredential

-- ## Definition 2.3: Zero-Knowledge Proof

/-- 公開入力を表す型 -/
structure PublicInput where
  data : ByteArray

/-- 秘密入力（witness）を表す型 -/
structure Witness where
  data : ByteArray

/-- ZKP証明を表す型 -/
structure Proof where
  bytes : ByteArray

/-- 関係式を表す型 -/
def Relation := PublicInput → Witness → Bool

/-- ゼロ知識証明 (Zero-Knowledge Proof) を表す構造体
    ZKP := (π, x) where π proves knowledge of w such that R(x, w) = 1 -/
structure ZeroKnowledgeProof where
  proof : Proof
  publicInput : PublicInput

namespace ZeroKnowledgeProof

/-- ZKP検証関数（公理化） -/
axiom verify : ZeroKnowledgeProof → Relation → Bool

/-- ZKPが有効かどうかを表す述語 -/
def isValid (zkp : ZeroKnowledgeProof) (relation : Relation) : Prop :=
  verify zkp relation = true

end ZeroKnowledgeProof

-- ## Definition 2.4: Anonymous Hash Identifier

/-- 監査区分識別子を表す型 -/
structure AuditSectionID where
  value : ByteArray

/-- 国民識別番号（マイナンバー等）を表す型 -/
structure NationalID where
  value : ByteArray

/-- 匿名ハッシュ識別子 (Anonymous Hash Identifier)
    AHI := H(AuditSectionID || NationalID) -/
structure AnonymousHashIdentifier where
  hash : Hash

namespace AnonymousHashIdentifier

/-- AHIを生成する関数（ハッシュ関数は公理化） -/
axiom fromComponents : AuditSectionID → NationalID → AnonymousHashIdentifier

end AnonymousHashIdentifier

-- ## Definition 2.5: Computational Resource Constraints

/-- デバイスの計算資源制約を表す構造体 -/
structure DeviceConstraints where
  storageAvailable : Nat      -- 利用可能ストレージ (bytes)
  computationAvailable : Nat  -- 利用可能計算量 (cycles)
  timeIdle : Nat              -- アイドル時間 (ms)
  deriving Repr, DecidableEq

/-- ZKP生成の資源要件を表す構造体 -/
structure ZKPRequirements where
  storagePrecomp : Nat        -- 事前計算の必要ストレージ
  computationPrecomp : Nat    -- 事前計算の必要計算量
  timePrecomp : Nat           -- 事前計算の必要時間
  timeRealtimeNonce : Nat     -- リアルタイムナンス結合の必要時間
  deriving Repr, DecidableEq
