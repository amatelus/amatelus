/-
# Verifiable Credential 定義

このファイルは、AMATELUSプロトコルのVerifiable Credential（検証可能資格情報）関連の型と定義を含みます。
-/

import AMATELUS.DID

-- ## Definition 2.2: Verifiable Credential

/-- VCのコンテキストを表す型 -/
structure Context where
  value : String
  deriving Repr, DecidableEq

/-- VCのタイプを表す型 -/
structure VCType where
  value : String
  deriving Repr, DecidableEq

/-- 失効情報を表す型 -/
structure RevocationInfo where
  statusListUrl : Option String
  deriving Repr, DecidableEq

/-- クレームタイプを表す型 -/
def ClaimTypeBasic := String

/-- クレーム識別子を表す型

    トラストアンカーが定義するクレームの一意な識別子。
    例: "政府_1" (住民票), "政府_2" (運転免許証)
-/
structure ClaimID where
  value : String
  deriving Repr, DecidableEq, BEq

/-- クレーム（主張）を表す型

    **設計:**
    - `data`: 構造化データ（JSON等）
    - `claimID`: クレームの識別子（トラストアンカーが定義）
      - `Some claimID`: 特定のクレームタイプ（住民票、運転免許証等）
      - `None`: クレームIDが指定されていない（汎用クレーム）
-/
structure Claims where
  data : String  -- 実際には構造化データ
  claimID : Option ClaimID  -- クレームの識別子
  deriving Repr, DecidableEq

/-- ClaimsからClaimIDを取得する関数（定義として実装）-/
def Claims.getClaimID (claims : Claims) : Option ClaimID :=
  claims.claimID

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

/-- AHIを生成する関数（定義として実装）

    AHI := H(AuditSectionID || NationalID)

    **手順:**
    1. AuditSectionIDとNationalIDのバイト列を連結
    2. 連結したバイト列をハッシュ化
    3. ハッシュ値を持つAnonymousHashIdentifierを構築

    この定義により、以下が保証される：
    - **決定性**: 同じ入力からは常に同じAHIが生成される
    - **不可逆性**: AHIから元のNationalIDを復元することは計算量的に困難
    - **一意性**: 異なる入力は（高確率で）異なるAHIを生成する
-/
noncomputable def fromComponents (auditSection : AuditSectionID) (nationalID : NationalID) : AnonymousHashIdentifier :=
  -- バイト列を連結してハッシュ化
  { hash := hashForDID (auditSection.value ++ nationalID.value) }

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

/-- AMATELUS固有のVerifiable Credential構造

    W3C VCを継承し、AMATELUS固有の1階層制限を型レベルで保証する。

    **1階層制限の型システム保証:**
    - `delegator: Option DID`により、階層は0または1のみに限定される
    - `None`: トラストアンカーが直接発行（0階層）
    - `Some anchorDID`: トラストアンカーが委任者経由で発行（1階層）
    - 受託者には委任者フィールドがないため、再委任は型システムで不可能

    **設計の利点:**
    - 型システムで1階層制限が自動的に保証される（数学的証明不要）
    - 2階層以上のVCは構造的に構築不可能
    - 委任チェーンの検証が単純化（Option型をチェックするだけ）

    参考: W3C VC Data Model 1.1に準拠しつつ、AMATELUS固有の制約を追加
-/
structure AMATELUSCredential extends W3CCredentialCore where
  -- AMATELUS固有フィールド
  delegator : Option DID  -- None = トラストアンカー直接発行、Some did = 委任者経由発行
  deriving Repr, DecidableEq

/-- 受託者認証VC

    トラストアンカーが受託者に発行する認証クレデンシャル。
    受託者が特定のクレームIDを発行する権限を持つことを証明する。

    **使用例:**
    政府（トラストアンカー）が自治体（受託者）に発行するVC：
    - issuer: 政府のDID
    - subject: 自治体のDID
    - delegator: Some 政府のDID（1階層：政府が委任）
    - authorizedClaimIDs: ["政府_1"]  -- 住民票の発行権限

    **1階層制限:**
    - このVCは`delegator: Some anchorDID`を持つため、1階層のVC
    - 受託者が発行するVCは`delegator: Some anchorDID`を持つ必要があり、再委任は不可能
-/
structure TrusteeVC extends AMATELUSCredential where
  -- 受託者固有のクレーム
  authorizedClaimIDs : List ClaimID  -- 発行可能なクレームIDのリスト
  trustLevel : Nat                    -- 信頼レベル (1-5)

/-- 国民識別情報VC

    政府機関が発行する国民識別情報（マイナンバーなど）を含むVC。
    プライバシー保護のため、AHIを使用して匿名化される。

    **1階層制限:**
    - トラストアンカーが直接発行: `delegator: None`（0階層）
    - 受託者経由で発行: `delegator: Some anchorDID`（1階層）
-/
structure NationalIDVC extends AMATELUSCredential where
  -- 国民ID固有のクレーム
  anonymousHashId : AnonymousHashIdentifier   -- 匿名ハッシュ識別子
  auditSection : AuditSectionID                -- 監査区分識別子

/-- 属性情報VC

    一般的な属性情報（年齢、住所、資格など）を証明するVC。
    汎用的なクレームタイプで、様々な発行者が発行できる。

    **1階層制限:**
    - トラストアンカーが直接発行: `delegator: None`（0階層）
    - 受託者経由で発行: `delegator: Some anchorDID`（1階層）
-/
structure AttributeVC extends AMATELUSCredential where
  -- 属性固有のクレーム
  claims : Claims                             -- 任意の構造化クレーム

/-- 検証者VC

    トラストアンカーが検証者に発行する認証クレデンシャル。
    検証者が特定のクレームタイプを検証する権限を持つことを証明する。

    偽警官対策: Holderはこのような検証者VCの提示を要求することで、
    正規の検証者であることを確認できる。

    **1階層制限:**
    - 通常、トラストアンカーが直接発行: `delegator: None`（0階層）
-/
structure VerifierVC extends AMATELUSCredential where
  -- 検証者固有のクレーム
  authorizedVerificationTypes : List ClaimTypeBasic  -- 検証可能なクレームタイプ
  verificationScope : String                          -- 検証の範囲（地域、組織など）

/-- クレーム定義VC

    トラストアンカーが自己署名で公開するクレーム定義。
    クレームIDとその意味を定義する。

    **使用例:**
    政府（トラストアンカー）が以下のようなクレーム定義VCを公開：
    - ClaimID: "政府_1", Description: "住民票", Schema: {...}
    - ClaimID: "政府_2", Description: "運転免許証", Schema: {...}

    検証者はトラストアンカーのDIDDocumentとともに、
    これらのクレーム定義VCをダウンロードしてWalletに登録する。

    **1階層制限:**
    - トラストアンカーが自己署名で発行: `delegator: None`（0階層）
-/
structure ClaimDefinitionVC extends AMATELUSCredential where
  -- クレーム定義固有のフィールド
  claimID : ClaimID                     -- クレームの一意な識別子
  description : String                  -- クレームの説明（人間可読）
  schema : String                       -- クレームのスキーマ（JSON Schema等）

/-- VCタイプの基本構造（型のみ）

    すべての具体的なVCタイプの和型。
    AMATELUSプロトコルで扱われるVCは、以下のいずれかの型を持つ：
    - TrusteeVC: 受託者認証
    - NationalIDVC: 国民識別情報
    - AttributeVC: 一般属性情報
    - VerifierVC: 検証者認証
    - ClaimDefinitionVC: クレーム定義（トラストアンカーが自己署名で公開）
-/
inductive VCTypeCore
  | trusteeVC : TrusteeVC → VCTypeCore
  | nationalIDVC : NationalIDVC → VCTypeCore
  | attributeVC : AttributeVC → VCTypeCore
  | verifierVC : VerifierVC → VCTypeCore
  | claimDefinitionVC : ClaimDefinitionVC → VCTypeCore

namespace VCTypeCore

/-- VCTypeからAMATELUS構造を取得 -/
def getAMATELUSCore : VCTypeCore → AMATELUSCredential
  | trusteeVC vc => vc.toAMATELUSCredential
  | nationalIDVC vc => vc.toAMATELUSCredential
  | attributeVC vc => vc.toAMATELUSCredential
  | verifierVC vc => vc.toAMATELUSCredential
  | claimDefinitionVC vc => vc.toAMATELUSCredential

/-- VCTypeからW3C基本構造を取得 -/
def getCore : VCTypeCore → W3CCredentialCore
  | trusteeVC vc => vc.toW3CCredentialCore
  | nationalIDVC vc => vc.toW3CCredentialCore
  | attributeVC vc => vc.toW3CCredentialCore
  | verifierVC vc => vc.toW3CCredentialCore
  | claimDefinitionVC vc => vc.toW3CCredentialCore

/-- VCTypeの発行者を取得 -/
def getIssuer (vc : VCTypeCore) : DID :=
  (getCore vc).issuer

/-- VCTypeの主体を取得 -/
def getSubject (vc : VCTypeCore) : DID :=
  (getCore vc).subject

/-- VCTypeの委任者を取得（1階層制限の検証に使用） -/
def getDelegator (vc : VCTypeCore) : Option DID :=
  (getAMATELUSCore vc).delegator

end VCTypeCore

/-- 正規の検証可能資格情報 (Valid Verifiable Credential)

    署名検証が成功するVC。
    暗号学的に正しく発行されたVCは、署名検証に成功する。

    **設計思想:**
    - VCの発行はIssuerの責任（署名は暗号ライブラリで生成）
    - プロトコルレベルでは「正規に発行されたVC」として抽象化
    - Verifierは署名検証のみに依存し、Issuer実装を信頼しない

    **抽象化の利点:**
    - Ed25519署名検証などの暗号的詳細を隠蔽
    - プロトコルの安全性証明が簡潔になる
    - Issuer実装の違いを抽象化（同じプロトコルで多様なIssuer実装が可能）
-/
structure ValidVC where
  -- VCの種類
  vcType : VCTypeCore
  -- 暗号学的に正しく発行されたという不変条件（抽象化）
  -- 実際のEd25519署名検証などの詳細は抽象化される

/-- 不正な検証可能資格情報 (Invalid Verifiable Credential)

    署名検証が失敗するVC。
    以下のいずれかの理由で不正：
    - 署名が改ざんされている
    - 発行者の秘密鍵が不正
    - VCの内容が改ざんされている
    - 署名検証に失敗する

    **Issuerバグの影響:**
    - バグのあるIssuerが生成したVCは`InvalidVC`として表現される
    - プロトコルの安全性には影響しない（当該VCのみが無効になる）
-/
structure InvalidVC where
  -- VCの種類
  vcType : VCTypeCore
  -- 不正な理由（デバッグ用、プロトコルには不要）
  reason : String

/-- 検証可能資格情報 (Verifiable Credential)

    正規のVCと不正なVCの和型。
    AMATELUSプロトコルで扱われるVCは、暗号学的に以下のいずれか：
    - valid: 正規に発行されたVC（署名検証が成功）
    - invalid: 不正なVC（署名検証が失敗）

    **設計の利点:**
    - VC検証の暗号的詳細（Ed25519署名検証など）を抽象化
    - プロトコルレベルでは「正規/不正」の区別のみが重要
    - Issuer実装のバグは`invalid`として表現され、プロトコルの安全性には影響しない

    **ZKPとの設計の一貫性:**
    - ZeroKnowledgeProofと同じパターン（Valid/Invalid + 和型）
    - 統一された形式検証アプローチ
-/
inductive VerifiableCredential
  | valid : ValidVC → VerifiableCredential
  | invalid : InvalidVC → VerifiableCredential

namespace VerifiableCredential

/-- VCから基本構造を取得 -/
def getCore : VerifiableCredential → W3CCredentialCore :=
  fun vc => match vc with
  | valid vvc => VCTypeCore.getCore vvc.vcType
  | invalid ivc => VCTypeCore.getCore ivc.vcType

/-- VCの発行者を取得 -/
def getIssuer (vc : VerifiableCredential) : DID :=
  (getCore vc).issuer

/-- VCの主体を取得 -/
def getSubject (vc : VerifiableCredential) : DID :=
  (getCore vc).subject

/-- VC検証関数（定義として実装）

    **設計の核心:**
    - 正規のVC（valid）: 常に検証成功（署名が有効）
    - 不正なVC（invalid）: 常に検証失敗（署名が無効）

    この単純な定義により、暗号的詳細（Ed25519署名検証など）を
    抽象化しつつ、プロトコルの安全性を形式的に証明できる。

    **Issuerバグの影響:**
    - バグのあるIssuerが生成したVCは`invalid`として表現される
    - `verifySignature (invalid _) = false`により、検証は失敗する
    - したがって、Issuerバグは当該VCのみに影響
-/
def verifySignature : VerifiableCredential → Bool
  | valid _ => true   -- 正規のVCは常に検証成功
  | invalid _ => false -- 不正なVCは常に検証失敗

/-- VCが有効かどうかを表す述語 -/
def isValid (vc : VerifiableCredential) : Prop :=
  verifySignature vc = true

/-- Theorem: 正規のVCは常に検証成功

    暗号学的に正しく発行されたVCは、署名検証が成功する。
    これは定義から自明だが、明示的に定理として示す。
-/
theorem valid_vc_passes :
  ∀ (vvc : ValidVC),
    isValid (valid vvc) := by
  intro vvc
  unfold isValid verifySignature
  rfl

/-- Theorem: 不正なVCは常に検証失敗

    暗号学的に不正なVCは、署名検証が失敗する。
    これにより、Issuerバグや改ざんされたVCが受け入れられないことを保証。
-/
theorem invalid_vc_fails :
  ∀ (ivc : InvalidVC),
    ¬isValid (invalid ivc) := by
  intro ivc
  unfold isValid verifySignature
  simp

end VerifiableCredential
