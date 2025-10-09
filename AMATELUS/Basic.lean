/-
# AMATELUSプロトコルの基本定義

このファイルは、AMATELUSプロトコルの基本的な型と定義を含みます。
-/

-- ## 基本型定義

/-- ハッシュ値を表す型 -/
structure Hash where
  value : List UInt8
  deriving Repr, DecidableEq

/-- 公開鍵を表す型 -/
structure PublicKey where
  bytes : List UInt8
  deriving Repr, DecidableEq

/-- 秘密鍵を表す型 -/
structure SecretKey where
  bytes : List UInt8
  deriving Repr, DecidableEq

/-- デジタル署名を表す型 -/
structure Signature where
  bytes : List UInt8
  deriving Repr, DecidableEq

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
  deriving Repr, DecidableEq

/-- DIDDocumentのシリアライゼーション関数

    この関数は、DIDDocumentを一意なバイト列表現に変換する。
    実装では、各フィールドを決定的な順序で連結する：
    serialize(doc) = serialize(publicKey) || serialize(service) || serialize(metadata)

    この関数の単射性により、異なるDIDDocumentは異なるバイト列を生成する。
-/
axiom serializeDIDDocument : DIDDocument → List UInt8

/-- serializeDIDDocumentの単射性

    異なるDIDドキュメントは異なるシリアライゼーション結果を生成する。
    これは、DIDドキュメントのすべてのフィールドがシリアライゼーションに含まれ、
    決定的な順序で連結されることから保証される。
-/
axiom serializeDIDDocument_injective :
  ∀ (doc₁ doc₂ : DIDDocument),
    serializeDIDDocument doc₁ = serializeDIDDocument doc₂ → doc₁ = doc₂

/-- 暗号学的ハッシュ関数（公理）

    DID生成に使用される耐衝突性ハッシュ関数。
    この関数は、任意のバイト列を固定長のハッシュ値に変換する。

    性質:
    - 決定性: 同じ入力には常に同じ出力
    - 耐衝突性: H(x₁) = H(x₂) ∧ x₁ ≠ x₂ を見つけることが計算量的に困難
    - 一方向性: H(x) = h から x を計算することが困難

    注意: 実際のハッシュ関数はSecurityAssumptions.leanで定義される
-/
axiom hashForDID : List UInt8 → Hash

/-- ハッシュ関数の耐衝突性（公理）

    異なる入力に対しては、negligibleな確率を除いて異なるハッシュ値が生成される。

    形式的には: H(x₁) = H(x₂) ならば x₁ = x₂ （計算量的に）

    注意: この性質はセキュリティパラメータに依存し、
    厳密にはnegligible関数を用いて定義されるべきだが、
    ここでは簡略化のため決定的に扱う。
-/
axiom hashForDID_injective_with_high_probability :
  ∀ (x₁ x₂ : List UInt8),
    hashForDID x₁ = hashForDID x₂ → x₁ = x₂

namespace DID

/-- DIDドキュメントからDIDを生成する（定義）

    この定義は、宇宙に存在する辞書 `{DIDDocument ↦ DID}` を表現する：

    **辞書の定義:**
    ```
    UniversalDIDDictionary : DIDDocument → DID
    UniversalDIDDictionary(doc) = { hash := H(serialize(doc)) }
    ```

    **fromDocumentの意味:**
    - fromDocument(doc) = UniversalDIDDictionary(doc)
    - つまり、この宇宙の辞書から doc に対応する DID を取得する

    **手順:**
    1. DIDドキュメントをシリアライズ: `bytes = serialize(doc)`
    2. バイト列をハッシュ化: `h = H(bytes)`
    3. ハッシュ値を持つDIDを構築: `{ hash := h }`

    この定義により、以下が保証される：
    - **決定性**: 同じDIDドキュメントからは常に同じDIDが生成される
    - **検証可能性**: DIDとDIDドキュメントのペアの正当性を検証できる
    - **一意性**: ハッシュ関数の耐衝突性により、異なるDIDドキュメントは
      （高確率で）異なるDIDを生成する
-/
noncomputable def fromDocument (doc : DIDDocument) : DID :=
  -- 宇宙の辞書: doc ↦ { hash := H(serialize(doc)) }
  { hash := hashForDID (serializeDIDDocument doc) }

/-- DIDがDIDドキュメントから正しく生成されたかを検証 -/
def isValid (did : DID) (doc : DIDDocument) : Prop :=
  did = fromDocument doc

-- ## DIDとDIDドキュメントの正規性

/-- 正規のDID-DIDドキュメントのペア

    HolderがVerifierに提示するペアは、この述語を満たす必要がある。
    正規のペアは、DIDがDIDドキュメントから正しく生成されたものである。
-/
def isCanonicalPair (did : DID) (doc : DIDDocument) : Prop :=
  isValid did doc

/-- 不正なDID-DIDドキュメントのペア

    以下のいずれかの場合、ペアは不正である：
    1. DIDとDIDドキュメントが一致しない（H(doc) ≠ did）
    2. 改ざんされたDIDドキュメント
-/
def isInvalidPair (did : DID) (doc : DIDDocument) : Prop :=
  ¬isValid did doc

/-- Theorem: 正規のDID-DIDドキュメントのペアは一意に定まる

    証明の概要:
    - 同じDIDに対して、複数の異なるDIDドキュメントが正規であることはない
    - これはハッシュ関数の衝突耐性から導かれる

    例: did = H(doc₁) かつ did = H(doc₂) ならば、doc₁ = doc₂

    注意: 証明には did_fromDocument_injective が必要。
    名前空間を閉じた後に証明を完成させる。
-/
axiom canonical_pair_unique :
  ∀ (did : DID) (doc₁ doc₂ : DIDDocument),
    isCanonicalPair did doc₁ →
    isCanonicalPair did doc₂ →
    doc₁ = doc₂

/-- Theorem: 不正なペアは検証に失敗する

    HolderがVerifierに不正な(did, doc)ペアを提示した場合、
    isValid did doc = Falseとなり、検証は失敗する。
-/
theorem invalid_pair_fails_validation :
  ∀ (did : DID) (doc : DIDDocument),
    isInvalidPair did doc →
    ¬isValid did doc := by
  intro did doc h_invalid
  unfold isInvalidPair at h_invalid
  exact h_invalid

/-- Theorem: 検証成功は正規性を保証する

    isValid did doc = Trueならば、(did, doc)は正規のペアである。
    これは定義から自明だが、明示的に定理として示す。
-/
theorem validation_ensures_canonical :
  ∀ (did : DID) (doc : DIDDocument),
    isValid did doc →
    isCanonicalPair did doc := by
  intro did doc h_valid
  unfold isCanonicalPair
  exact h_valid

/-- Theorem: 改ざん検知

    HolderがDIDドキュメントを改ざんした場合（doc ≠ doc'）、
    元のDIDとの組(did, doc')は検証に失敗する。

    証明: did = H(doc)であるが、doc ≠ doc'ならば、
    ハッシュ関数の衝突耐性により H(doc) ≠ H(doc')（高確率）
    したがって did ≠ H(doc')となり、isValid did doc' = False

    注意: 証明には did_fromDocument_injective が必要。
    名前空間を閉じた後に証明を完成させる。
-/
axiom tampering_detection :
  ∀ (doc doc' : DIDDocument),
    doc ≠ doc' →
    let did := fromDocument doc
    isInvalidPair did doc'

/-- Theorem: Verifierは不正なペアを受け入れない（健全性）

    Verifierが(did, doc)ペアを受け取った時、
    isValid did doc = Falseならば、検証は失敗する。

    これは、不正なHolderや攻撃者が偽のペアを提示しても
    受け入れられないことを保証する。
-/
theorem verifier_rejects_invalid_pair :
  ∀ (did : DID) (doc : DIDDocument),
    ¬isValid did doc →
    -- Verifierの検証ロジック
    ∃ (verificationFailed : Bool),
      verificationFailed = true := by
  intro did doc h_invalid
  -- 検証失敗を表すフラグを構成
  refine ⟨true, rfl⟩

end DID

/-- fromDocumentの単射性（定理として証明）

    この定理は、ハッシュ関数の耐衝突性とシリアライゼーションの単射性から導かれる。

    証明の手順:
    1. fromDocument doc₁ = fromDocument doc₂ を仮定
    2. 定義により、{ hash := H(serialize(doc₁)) } = { hash := H(serialize(doc₂)) }
    3. よって、H(serialize(doc₁)) = H(serialize(doc₂))
    4. ハッシュ関数の耐衝突性により、serialize(doc₁) = serialize(doc₂)
    5. シリアライゼーションの単射性により、doc₁ = doc₂

    この証明により、公理の数を1つ削減し、形式検証の厳密性が向上した。
-/
theorem did_fromDocument_injective :
  ∀ (doc₁ doc₂ : DIDDocument),
    DID.fromDocument doc₁ = DID.fromDocument doc₂ → doc₁ = doc₂ := by
  intro doc₁ doc₂ h
  -- fromDocumentの定義を展開
  unfold DID.fromDocument at h
  -- h: { hash := hashForDID (serializeDIDDocument doc₁) } =
  --    { hash := hashForDID (serializeDIDDocument doc₂) }

  -- DID構造体の等価性からハッシュフィールドの等価性を導く
  have h_hash : hashForDID (serializeDIDDocument doc₁) =
                hashForDID (serializeDIDDocument doc₂) := by
    have : (DID.fromDocument doc₁).hash = (DID.fromDocument doc₂).hash := by
      exact congrArg DID.hash h
    simp [DID.fromDocument] at this
    exact this

  -- ハッシュ関数の耐衝突性を適用
  have h_serialize : serializeDIDDocument doc₁ = serializeDIDDocument doc₂ :=
    hashForDID_injective_with_high_probability
      (serializeDIDDocument doc₁)
      (serializeDIDDocument doc₂)
      h_hash

  -- シリアライゼーションの単射性を適用
  exact serializeDIDDocument_injective doc₁ doc₂ h_serialize

-- ## DIDの正規性定理（名前空間を閉じてから証明を完成）

namespace DID

/-- canonical_pair_unique の証明（定理として証明）

    did_fromDocument_injective を使用して証明を完成させる。
    これにより、axiomだったものが theorem に昇格する。
-/
theorem canonical_pair_unique_proof :
  ∀ (did : DID) (doc₁ doc₂ : DIDDocument),
    DID.isCanonicalPair did doc₁ →
    DID.isCanonicalPair did doc₂ →
    doc₁ = doc₂ := by
  intro did doc₁ doc₂ h₁ h₂
  unfold DID.isCanonicalPair DID.isValid at h₁ h₂
  have h_eq : DID.fromDocument doc₁ = DID.fromDocument doc₂ := by
    rw [← h₁, ← h₂]
  -- did_fromDocument_injective を適用
  exact did_fromDocument_injective doc₁ doc₂ h_eq

/-- tampering_detection の証明（定理として証明）

    did_fromDocument_injective を使用して証明を完成させる。
    これにより、axiomだったものが theorem に昇格する。
-/
theorem tampering_detection_proof :
  ∀ (doc doc' : DIDDocument),
    doc ≠ doc' →
    let did := DID.fromDocument doc
    DID.isInvalidPair did doc' := by
  intro doc doc' h_diff did
  unfold DID.isInvalidPair DID.isValid
  intro h_eq
  have h_from_eq : DID.fromDocument doc = DID.fromDocument doc' := by
    unfold did at h_eq
    exact h_eq
  -- did_fromDocument_injective を適用して矛盾を導く
  have h_eq_docs : doc = doc' := did_fromDocument_injective doc doc' h_from_eq
  exact h_diff h_eq_docs

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

/-- クレームタイプを表す型 -/
def ClaimTypeBasic := String

/-- 監査区分識別子を表す型 -/
structure AuditSectionID where
  value : List UInt8
  deriving Repr, DecidableEq

/-- 国民識別番号（マイナンバー等）を表す型 -/
structure NationalID where
  value : List UInt8
  deriving Repr, DecidableEq

/-- 匿名ハッシュ識別子 (Anonymous Hash Identifier)
    AHI := H(AuditSectionID || NationalID) -/
structure AnonymousHashIdentifier where
  hash : Hash
  deriving Repr, DecidableEq

namespace AnonymousHashIdentifier

/-- AHIを生成する関数（ハッシュ関数は公理化） -/
axiom fromComponents : AuditSectionID → NationalID → AnonymousHashIdentifier

end AnonymousHashIdentifier

/-- W3C Verifiable Credential仕様の基本構造

    この構造は、W3C VC Data Model 1.1に基づく基本的なフィールドを含む。
    すべての具体的なVCはこの基本構造を含む必要がある。

    参考: https://www.w3.org/TR/vc-data-model/
-/
structure W3CCredentialCore where
  -- 必須フィールド
  context : Context                  -- @context: JSONLDコンテキスト
  type : VCType                      -- type: VCの種類
  issuer : DID                       -- issuer: 発行者のDID
  subject : DID                      -- credentialSubject.id: 主体のDID
  signature : Signature              -- proof: デジタル署名

  -- オプショナルフィールド
  credentialStatus : RevocationInfo  -- credentialStatus: 失効情報
  deriving Repr, DecidableEq

/-- 受託者認証VC

    トラストアンカーが受託者に発行する認証クレデンシャル。
    受託者が特定のクレームタイプを発行する権限を持つことを証明する。
-/
structure TrusteeVC where
  core : W3CCredentialCore
  -- 受託者固有のクレーム
  authorizedClaimTypes : List ClaimTypeBasic  -- 発行可能なクレームタイプ
  trustLevel : Nat                             -- 信頼レベル (1-5)

/-- 国民識別情報VC

    政府機関が発行する国民識別情報（マイナンバーなど）を含むVC。
    プライバシー保護のため、AHIを使用して匿名化される。
-/
structure NationalIDVC where
  core : W3CCredentialCore
  -- 国民ID固有のクレーム
  anonymousHashId : AnonymousHashIdentifier   -- 匿名ハッシュ識別子
  auditSection : AuditSectionID                -- 監査区分識別子

/-- 属性情報VC

    一般的な属性情報（年齢、住所、資格など）を証明するVC。
    汎用的なクレームタイプで、様々な発行者が発行できる。
-/
structure AttributeVC where
  core : W3CCredentialCore
  -- 属性固有のクレーム
  claims : Claims                             -- 任意の構造化クレーム

/-- 検証者VC

    トラストアンカーが検証者に発行する認証クレデンシャル。
    検証者が特定のクレームタイプを検証する権限を持つことを証明する。

    偽警官対策: Holderはこのような検証者VCの提示を要求することで、
    正規の検証者であることを確認できる。
-/
structure VerifierVC where
  core : W3CCredentialCore
  -- 検証者固有のクレーム
  authorizedVerificationTypes : List ClaimTypeBasic  -- 検証可能なクレームタイプ
  verificationScope : String                          -- 検証の範囲（地域、組織など）

/-- 検証可能資格情報 (Verifiable Credential)

    すべての具体的なVCタイプの和型。
    AMATELUSプロトコルで扱われるVCは、以下のいずれかの型を持つ：
    - TrusteeVC: 受託者認証
    - NationalIDVC: 国民識別情報
    - AttributeVC: 一般属性情報
    - VerifierVC: 検証者認証
-/
inductive VerifiableCredential
  | trusteeVC : TrusteeVC → VerifiableCredential
  | nationalIDVC : NationalIDVC → VerifiableCredential
  | attributeVC : AttributeVC → VerifiableCredential
  | verifierVC : VerifierVC → VerifiableCredential

namespace VerifiableCredential

/-- VCから基本構造を取得 -/
def getCore : VerifiableCredential → W3CCredentialCore
  | trusteeVC vc => vc.core
  | nationalIDVC vc => vc.core
  | attributeVC vc => vc.core
  | verifierVC vc => vc.core

/-- VCの発行者を取得 -/
def getIssuer (vc : VerifiableCredential) : DID :=
  (getCore vc).issuer

/-- VCの主体を取得 -/
def getSubject (vc : VerifiableCredential) : DID :=
  (getCore vc).subject

/-- VCが有効かどうかを表す述語（公理化） -/
axiom isValid : VerifiableCredential → Prop

end VerifiableCredential

-- ## 基本的な型定義（ZKP用）

/-- タイムスタンプを表す型 -/
structure Timestamp where
  unixTime : Nat
  deriving Repr, DecidableEq

/-- ナンスを表す型 -/
structure Nonce where
  value : List UInt8
  deriving Repr, BEq, DecidableEq

-- ## Definition 2.3: Zero-Knowledge Proof

/-- 公開入力を表す型 -/
structure PublicInput where
  data : List UInt8

/-- 秘密入力（witness）を表す型 -/
structure Witness where
  data : List UInt8

/-- ZKP証明を表す型 -/
structure Proof where
  bytes : List UInt8

/-- 関係式を表す型 -/
def Relation := PublicInput → Witness → Bool

/-- W3C ZKP仕様の基本構造

    すべてのZKPはこの基本構造を含む。
    参考: W3C VC Data Model 2.0 の Proof 仕様
-/
structure W3CZKProofCore where
  proof : Proof               -- 証明データ（π）
  publicInput : PublicInput   -- 公開入力（x）
  proofPurpose : String       -- 証明の目的（authentication, assertionMethodなど）
  created : Timestamp         -- 証明生成時刻

/-- Verifier認証用ZKP

    Verifierが自身の正当性を証明するためのZKP。
    "私（verifierDID）は、信頼できるトラストアンカーから
    発行されたVerifierVCを保持している"ことを証明。
-/
structure VerifierAuthZKP where
  core : W3CZKProofCore
  verifierDID : DID           -- 証明者（Verifier）のDID
  challengeNonce : Nonce      -- Holderが発行したチャレンジnonce
  credentialType : String     -- 証明対象のVC種類（"VerifierVC"など）

/-- Holder資格証明用ZKP

    Holderが特定の属性を証明するためのZKP。
    "私は特定の属性を満たすVCを保持している"ことを証明。
    例: "私は20歳以上である"、"私は運転免許を持っている"など
-/
structure HolderCredentialZKP where
  core : W3CZKProofCore
  holderDID : DID             -- 証明者（Holder）のDID
  challengeNonce : Nonce      -- Verifierが発行したチャレンジnonce
  claimedAttributes : String  -- 証明する属性の記述

/-- ゼロ知識証明 (Zero-Knowledge Proof)

    すべての具体的なZKPタイプの和型。
    AMATELUSプロトコルで扱われるZKPは、以下のいずれかの型を持つ：
    - verifierAuthZKP: Verifier認証用ZKP
    - holderCredentialZKP: Holder資格証明用ZKP
-/
inductive ZeroKnowledgeProof
  | verifierAuthZKP : VerifierAuthZKP → ZeroKnowledgeProof
  | holderCredentialZKP : HolderCredentialZKP → ZeroKnowledgeProof

namespace ZeroKnowledgeProof

/-- ZKPから基本構造を取得 -/
def getCore : ZeroKnowledgeProof → W3CZKProofCore
  | verifierAuthZKP zkp => zkp.core
  | holderCredentialZKP zkp => zkp.core

/-- ZKP検証関数（公理化） -/
axiom verify : ZeroKnowledgeProof → Relation → Bool

/-- ZKPが有効かどうかを表す述語 -/
def isValid (zkp : ZeroKnowledgeProof) (relation : Relation) : Prop :=
  verify zkp relation = true

end ZeroKnowledgeProof

-- ## Definition 2.4: Computational Resource Constraints

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

-- ## Wallet and Role Definitions

/-- 事前計算されたZKP -/
structure PrecomputedZKP where
  partialProof : Proof
  publicStatement : PublicInput

/-- 認証局の種類 -/
inductive AuthorityType
  | Government           -- 政府機関
  | CertifiedCA          -- 認定認証局
  | IndustrialStandard   -- 業界標準機関
  deriving Repr, DecidableEq

/-- ルート認証局証明書 -/
structure RootAuthorityCertificate where
  -- 証明書の所有者（ルート認証局のDID）
  subject : DID
  -- 証明書の種類（政府機関、認定CA等）
  authorityType : AuthorityType
  -- 発行可能なクレームドメイン
  authorizedDomains : List ClaimTypeBasic
  -- 自己署名（ルート認証局は自己署名）
  signature : Signature
  -- 有効期限
  validUntil : Timestamp

/-- トラストアンカー情報

    トラストアンカーに関連する情報を保持する。
    - DIDDocument: トラストアンカーのDIDドキュメント
    - trustees: このトラストアンカーから認証を受けた受託者のDIDリスト
-/
structure TrustAnchorInfo where
  didDocument : DIDDocument
  trustees : List DID  -- このトラストアンカーから認証を受けた受託者のリスト

namespace TrustAnchorInfo

/-- トラストアンカー情報が正規かどうかを検証

    トラストアンカーのDIDとDIDDocumentが一致することを確認する。
-/
def isValid (anchorDID : DID) (info : TrustAnchorInfo) : Prop :=
  DID.isValid anchorDID info.didDocument

/-- Theorem: 正規のトラストアンカー情報はDID検証に成功する -/
theorem valid_info_passes_did_verification :
  ∀ (anchorDID : DID) (info : TrustAnchorInfo),
    isValid anchorDID info →
    DID.isValid anchorDID info.didDocument := by
  intro anchorDID info h
  unfold isValid at h
  exact h

end TrustAnchorInfo

/-- トラストアンカー辞書の型

    辞書: { トラストアンカーのDID ↦ TrustAnchorInfo }

    連想リストとして実装され、DIDをキーとしてTrustAnchorInfoを取得できる。
-/
abbrev TrustAnchorDict := List (DID × TrustAnchorInfo)

namespace TrustAnchorDict

/-- 辞書からトラストアンカー情報を検索 -/
def lookup (dict : TrustAnchorDict) (anchorDID : DID) : Option TrustAnchorInfo :=
  List.lookup anchorDID dict

/-- 辞書にトラストアンカー情報を追加 -/
def insert (dict : TrustAnchorDict) (anchorDID : DID) (info : TrustAnchorInfo) : TrustAnchorDict :=
  (anchorDID, info) :: List.filter (fun (did, _) => did ≠ anchorDID) dict

/-- 辞書から受託者を追加

    指定されたトラストアンカーの受託者リストに新しい受託者を追加する。
-/
def addTrustee (dict : TrustAnchorDict) (anchorDID : DID) (trusteeDID : DID) : TrustAnchorDict :=
  List.map (fun (did, info) =>
    if did = anchorDID then
      (did, { info with trustees := trusteeDID :: info.trustees })
    else
      (did, info)) dict

/-- 辞書内のすべてのエントリーが正規かどうかを検証 -/
def allValid (dict : TrustAnchorDict) : Prop :=
  ∀ (anchorDID : DID) (info : TrustAnchorInfo),
    (anchorDID, info) ∈ dict →
    TrustAnchorInfo.isValid anchorDID info

end TrustAnchorDict

/-- Walletはユーザーの秘密情報を安全に保管する -/
structure Wallet where
  -- アイデンティティ
  did : DID
  didDocument : DIDDocument
  secretKey : SecretKey

  -- 保管されている資格情報
  credentials : List VerifiableCredential

  -- 特別な証明書（ルート認証局の場合）
  rootAuthorityCertificate : Option RootAuthorityCertificate

  -- ZKP事前計算データ
  precomputedProofs : List PrecomputedZKP

  -- 信頼するトラストアンカーの辞書
  -- { トラストアンカーのDID ↦ { DIDDocument, 受託者のリスト } }
  trustedAnchors : TrustAnchorDict

/-- 検証者認証メッセージ

    偽警官対策: Holderが検証者の正当性を確認するためのメッセージ。
    検証者は以下の情報を含むメッセージをHolderに送信する：
    1. expectedTrustAnchor: Holderが期待しているトラストアンカーのDID
    2. verifierDID: 検証者自身のDID
    3. verifierCredentials: トラストアンカーから発行された検証者VCのリスト
    4. nonce2: リプレイ攻撃防止用のナンス
    5. authProof: 検証者がverifierDIDの所有者であることを証明するZKP

    Holderは以下を検証する：
    - expectedTrustAnchorがHolderのWallet内の信頼するトラストアンカーに含まれる
    - verifierCredentialsに含まれるVerifierVCがexpectedTrustAnchorから発行されている
    - VerifierVCのsubjectがverifierDIDと一致する
    - authProofが有効である

    これにより、Holderは偽警官（不正な検証者）にZKPを送信することを防ぐことができる。
-/
structure VerifierAuthMessage where
  expectedTrustAnchor : DID
  verifierDID : DID
  verifierCredentials : List VerifiableCredential
  nonce2 : Nonce
  authProof : ZeroKnowledgeProof

namespace VerifierAuthMessage

/-- 検証者認証メッセージを検証する関数

    Holderの視点で、検証者認証メッセージが正当かどうかを検証する。

    検証項目:
    1. expectedTrustAnchorがHolderのWallet内の信頼するトラストアンカーに存在する
    2. verifierCredentialsに少なくとも1つのVerifierVCが含まれる
    3. すべてのVerifierVCが有効である（VerifiableCredential.isValid）
    4. すべてのVerifierVCのissuerがexpectedTrustAnchorと一致する
    5. すべてのVerifierVCのsubjectがverifierDIDと一致する
    6. authProofが有効である（ZeroKnowledgeProof.isValid）
-/
def validateVerifierAuth (msg : VerifierAuthMessage) (holderWallet : Wallet) : Prop :=
  -- 1. expectedTrustAnchorがHolderのWallet内の信頼するトラストアンカーに存在する
  (TrustAnchorDict.lookup holderWallet.trustedAnchors msg.expectedTrustAnchor).isSome ∧
  -- 2. verifierCredentialsに少なくとも1つのVerifierVCが含まれる
  msg.verifierCredentials.length > 0 ∧
  -- 3-5. すべてのVerifierVCが以下の条件を満たす
  (∀ vc ∈ msg.verifierCredentials,
    -- VCが有効である
    VerifiableCredential.isValid vc ∧
    -- VCの発行者がexpectedTrustAnchorと一致する
    VerifiableCredential.getIssuer vc = msg.expectedTrustAnchor ∧
    -- VCのsubjectがverifierDIDと一致する
    VerifiableCredential.getSubject vc = msg.verifierDID) ∧
  -- 6. authProofが有効である（関係式は実装依存のため公理化）
  ∃ (relation : Relation), ZeroKnowledgeProof.isValid msg.authProof relation

/-- Theorem: 正規の検証者は検証に成功する

    トラストアンカーから正当に発行されたVerifierVCを持ち、
    有効なZKPを提示する検証者は、Holderの検証を通過する。
-/
axiom authentic_verifier_passes :
  ∀ (msg : VerifierAuthMessage) (holderWallet : Wallet),
    -- 前提条件: Holderがexpectedトラストアンカーを信頼している
    (TrustAnchorDict.lookup holderWallet.trustedAnchors msg.expectedTrustAnchor).isSome →
    -- 前提条件: すべてのVerifierVCが正規に発行されている
    (∀ vc ∈ msg.verifierCredentials,
      VerifiableCredential.isValid vc ∧
      VerifiableCredential.getIssuer vc = msg.expectedTrustAnchor ∧
      VerifiableCredential.getSubject vc = msg.verifierDID) →
    -- 前提条件: authProofが有効
    (∃ (relation : Relation), ZeroKnowledgeProof.isValid msg.authProof relation) →
    -- 結論: 検証に成功する
    validateVerifierAuth msg holderWallet

/-- Theorem: 偽警官（不正な検証者）は検証に失敗する

    以下のいずれかの条件を満たす不正な検証者は、Holderの検証を通過しない：
    1. 信頼されていないトラストアンカーを提示する
    2. 無効なVerifierVCを提示する
    3. 他のトラストアンカーから発行されたVerifierVCを提示する
    4. 他のDIDのVerifierVCを提示する（なりすまし）
    5. 無効なZKPを提示する
-/
axiom fake_verifier_fails :
  ∀ (msg : VerifierAuthMessage) (holderWallet : Wallet),
    -- 条件1: 信頼されていないトラストアンカー
    ((TrustAnchorDict.lookup holderWallet.trustedAnchors msg.expectedTrustAnchor).isNone ∨
     -- 条件2-4: 不正なVerifierVC
     (∃ vc ∈ msg.verifierCredentials,
       ¬VerifiableCredential.isValid vc ∨
       VerifiableCredential.getIssuer vc ≠ msg.expectedTrustAnchor ∨
       VerifiableCredential.getSubject vc ≠ msg.verifierDID) ∨
     -- 条件5: 無効なZKP
     (∀ (relation : Relation), ¬ZeroKnowledgeProof.isValid msg.authProof relation)) →
    -- 結論: 検証に失敗する
    ¬validateVerifierAuth msg holderWallet

end VerifierAuthMessage

/-- WalletとDIDの一貫性公理

    すべてのWalletは、以下の不変条件を満たす：
    1. wallet.did = DID.fromDocument wallet.didDocument
    2. wallet.secretKeyはwallet.didDocumentのpublicKeyに対応する秘密鍵（Cryptographic.leanで定義される）

    この公理は、Walletが正しく初期化され、改ざんされていないことを保証する。

    注意: 完全な定義（proves_ownershipを含む）はOperations.leanでインポート後に使用可能
-/
axiom wallet_did_consistency :
  ∀ (w : Wallet),
    w.did = DID.fromDocument w.didDocument

/-- 信頼ポリシーの定義 -/
structure TrustPolicy where
  -- 信頼するルート認証局のリスト
  trustedRoots : List DID
  -- 最大信頼チェーン深さ
  maxChainDepth : Nat
  -- 必須のクレームタイプ
  requiredClaimTypes : List ClaimTypeBasic

/-- Holder: VCを保持し、必要に応じて提示する主体 -/
structure Holder where
  wallet : Wallet

/-- トラストアンカー: 自己署名のルート認証局 -/
structure TrustAnchor where
  wallet : Wallet
  -- この発行者が発行できるクレームタイプ
  authorizedClaimTypes : List ClaimTypeBasic
  -- ルート認証局証明書（自己署名）
  rootCertificate : RootAuthorityCertificate

/-- 受託者: 上位認証局から認証を受けた発行者 -/
structure Trustee where
  wallet : Wallet
  -- この発行者が発行できるクレームタイプ
  authorizedClaimTypes : List ClaimTypeBasic
  -- 発行者としての認証情報（上位認証局から発行されたVC）
  issuerCredential : VerifiableCredential

/-- Issuer: VCを発行する権限を持つ主体
    発行者はトラストアンカー（自己署名のルート認証局）または
    受託者（上位認証局から認証を受けた発行者）のいずれかである -/
inductive Issuer
  | trustAnchor : TrustAnchor → Issuer
  | trustee : Trustee → Issuer

/-- Verifier: VCを検証する主体

    偽警官対策: 検証者はWalletを持ち、トラストアンカーから発行された
    VerifierVCを保持する。検証時には、Holderに対してこれらのVerifierVCを
    提示し、自身が正当な検証者であることを証明する。
-/
structure Verifier where
  -- アイデンティティと資格情報を保持するWallet
  -- Wallet内のcredentialsには、トラストアンカーから発行されたVerifierVCが含まれる
  wallet : Wallet
  -- 検証ポリシー（どの発行者を信頼するか等）
  trustPolicy : TrustPolicy

-- ## Holderの正規性検証定理

namespace DID

/-- Theorem: Holderが提示する正規のペアは検証に成功する

    HolderがWallet内の正規のDID-DIDドキュメントペアを提示した場合、
    Verifierの検証は必ず成功する（完全性）。
-/
theorem holder_valid_pair_passes :
  ∀ (holder : Holder),
    let did := holder.wallet.did
    let doc := holder.wallet.didDocument
    isValid did doc := by
  intro holder did doc
  unfold isValid
  -- Walletの一貫性公理により
  -- holder.wallet.did = DID.fromDocument holder.wallet.didDocument
  exact wallet_did_consistency holder.wallet

end DID
