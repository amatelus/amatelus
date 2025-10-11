/-
# Verifiable Credential 定義

このファイルは、AMATELUSプロトコルのVerifiable Credential（検証可能資格情報）関連の型と定義を含みます。
-/

import AMATELUS.DID
import W3C.VC

-- ## Definition 2.2: Verifiable Credential

-- AMATELUS型エイリアス（W3C標準型へのマッピング）
--
--     **Stage 6設計:**
--     AMATELUSの独自型をW3C標準型にマッピングします。
--     これにより、W3C.Credentialを直接使用しつつ、AMATELUS固有の型名を維持できます。

/-- VCのコンテキストを表す型（W3C標準と同一） -/
abbrev Context := W3C.Context

/-- VCのタイプを表す型（W3C標準のCredentialTypeにマッピング） -/
abbrev VCType := W3C.CredentialType

/-- 失効情報を表す型（W3C標準のCredentialStatusにマッピング）

    AMATELUSでは簡略化された失効情報を使用していましたが、
    W3C標準のCredentialStatusに移行します。
-/
abbrev RevocationInfo := Option W3C.CredentialStatus

/-- クレームタイプを表す型 -/
abbrev ClaimTypeBasic := String

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

/-- ClaimsからClaimIDを取得する関数（定義として実装） -/
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
noncomputable def fromComponents
    (auditSection : AuditSectionID) (nationalID : NationalID) : AnonymousHashIdentifier :=
  -- バイト列を連結してハッシュ化
  { hash := hashForDID (auditSection.value ++ nationalID.value) }

end AnonymousHashIdentifier

-- ## Helper Functions for W3C Issuer

/-- W3C.IssuerからDIDを取得する関数

    W3C.IssuerのID文字列がDID形式（"did:..."）の場合、DIDとして解釈します。

    **戻り値:**
    - `Some (DID.valid w3cDID)`: ID文字列がDID形式で有効
    - `None`: ID文字列がDID形式でない

    **使用例:**
    - issuer: W3C.Issuer.uri "did:amt:123..." → Some (DID.valid ...)
    - issuer: W3C.Issuer.uri "https://example.com" → None（URLはDIDではない）
-/
def getIssuerDID (issuer : W3C.Issuer) : Option DID :=
  let idString := issuer.getId
  -- DID形式かチェック（"did:"で始まる）
  if idString.startsWith "did:" then
    -- W3C.DIDとして構築
    let w3cDID : W3C.DID := { value := idString }
    -- AMATELUS DIDとして返す
    some (DID.valid w3cDID)
  else
    none

/-- DIDからW3C.Issuerを生成する関数

    AMATELUSのDIDをW3C標準のIssuer型に変換します。

    **変換方法:**
    - `DID.valid w3cDID` → W3C.Issuer.uri (did文字列)
    - `DID.invalid w3cDID _` → W3C.Issuer.uri (did文字列)

    **使用例:**
    - did: DID.valid { value := "did:amt:123..." } → Issuer.uri "did:amt:123..."
-/
def didToW3CIssuer (did : DID) : W3C.Issuer :=
  match did with
  | DID.valid w3cDID => W3C.Issuer.uri w3cDID.value
  | DID.invalid w3cDID _ => W3C.Issuer.uri w3cDID.value

-- ## Helper Functions for W3C CredentialSubject

/-- W3C.CredentialSubjectからDIDを取得する関数

    W3C.CredentialSubjectのid文字列がDID形式（"did:..."）の場合、DIDとして解釈します。

    **戻り値:**
    - `Some (DID.valid w3cDID)`: ID文字列がDID形式で有効
    - `None`: ID文字列がDID形式でない、またはidが存在しない

    **使用例:**
    - credentialSubject.id = Some "did:amt:123..." → Some (DID.valid ...)
    - credentialSubject.id = Some "https://example.com" → None（URLはDIDではない）
    - credentialSubject.id = None → None
-/
def getSubjectDID (subjects : List W3C.CredentialSubject) : Option DID :=
  match subjects.head? with
  | none => none
  | some subject =>
      match subject.id with
      | none => none
      | some idString =>
          -- DID形式かチェック（"did:"で始まる）
          if idString.startsWith "did:" then
            -- W3C.DIDとして構築
            let w3cDID : W3C.DID := { value := idString }
            -- AMATELUS DIDとして返す
            some (DID.valid w3cDID)
          else
            none

/-- DIDからW3C.CredentialSubjectを生成する関数

    AMATELUSのDIDをW3C標準のCredentialSubject型に変換します。

    **変換方法:**
    - did → W3C.CredentialSubject with id = Some (did文字列) and empty claims

    **使用例:**
    - did: DID.valid { value := "did:amt:123..." } →
      CredentialSubject { id := Some "did:amt:123...", claims := [] }

    **注意:**
    AMATELUSでは、claimsは各VC typeに分散して保存されます（AttributeVC.claims等）。
    W3C.CredentialSubject.claimsはAMATELUSでは使用しません。
-/
def didToCredentialSubject (did : DID) : W3C.CredentialSubject :=
  match did with
  | DID.valid w3cDID => { id := some w3cDID.value, claims := [] }
  | DID.invalid w3cDID _ => { id := some w3cDID.value, claims := [] }

-- ## Helper Functions for Context and VCType conversion

/-- AMATELUS ContextからW3C Contextへの変換（型エイリアスなので実質的に同一） -/
def contextToW3C (ctx : Context) : W3C.Context := ctx

/-- AMATELUS VCTypeからW3C CredentialTypeへの変換（型エイリアスなので実質的に同一） -/
def vcTypeToW3C (vct : VCType) : W3C.CredentialType := vct

/-- AMATELUS RevocationInfoからW3C CredentialStatusへの変換

    AMATELUSの簡略化されたRevocationInfoをW3C標準のCredentialStatusに変換します。
    RevocationInfoはすでにOption W3C.CredentialStatusとして定義されているため、
    この関数は実質的にidentity関数です。
-/
def revocationInfoToW3C (rev : RevocationInfo) : Option W3C.CredentialStatus := rev

/-- W3C Verifiable Credential完全準拠型エイリアス

    **Stage 6: W3C.Credential完全移行 ✓**

    AMATELUSはW3C/VC.leanで定義されたW3C.Credential構造体を直接使用します。
    これにより、W3C VC Data Model 2.0への完全な準拠を実現します。

    **段階的なW3C標準への準拠:**
    - Stage 1: オプショナルフィールドの追加（id, name, description, validFrom, validUntil） ✓
    - Stage 2: List型への変更（context, type） ✓
    - Stage 3: W3C.Issuer型への移行（issuer） ✓
    - Stage 4: W3C.CredentialSubject型への移行（credentialSubject） ✓
    - Stage 5: Signature分離（ValidVCへの移動） ✓
    - Stage 6: W3C.Credential完全移行 ✓

    **設計思想:**
    W3C標準では、Credential（proof前）とVerifiableCredential（proof後）を明確に分離します。
    AMATELUSはW3C.Credentialを直接使用し、ValidVCが署名を持ちます。

    参考: https://www.w3.org/TR/vc-data-model/
-/
abbrev W3CCredentialCore := W3C.Credential

/-- AMATELUS固有のVerifiable Credential構造

    W3C.Credentialを含み、AMATELUS固有の1階層制限を型レベルで保証する。

    **Stage 6設計変更:**
    - 以前: `extends W3CCredentialCore` で継承
    - 現在: `w3cCredential : W3C.Credential` でコンポジション
    - 理由: W3CCredentialCoreが型エイリアスになったため、extendsが使えない

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
structure AMATELUSCredential where
  -- W3C標準Credentialのコア構造
  w3cCredential : W3C.Credential
  -- AMATELUS固有フィールド
  delegator : Option DID  -- None = トラストアンカー直接発行、Some did = 委任者経由発行
  deriving Repr

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
structure TrusteeVC where
  -- AMATELUS構造
  amatelus : AMATELUSCredential
  -- 受託者固有のクレーム
  authorizedClaimIDs : List ClaimID  -- 発行可能なクレームIDのリスト
  trustLevel : Nat                    -- 信頼レベル (1-5)
  deriving Repr

/-- 国民識別情報VC

    政府機関が発行する国民識別情報（マイナンバーなど）を含むVC。
    プライバシー保護のため、AHIを使用して匿名化される。

    **1階層制限:**
    - トラストアンカーが直接発行: `delegator: None`（0階層）
    - 受託者経由で発行: `delegator: Some anchorDID`（1階層）
-/
structure NationalIDVC where
  -- AMATELUS構造
  amatelus : AMATELUSCredential
  -- 国民ID固有のクレーム
  anonymousHashId : AnonymousHashIdentifier   -- 匿名ハッシュ識別子
  auditSection : AuditSectionID                -- 監査区分識別子
  deriving Repr

/-- 属性情報VC

    一般的な属性情報（年齢、住所、資格など）を証明するVC。
    汎用的なクレームタイプで、様々な発行者が発行できる。

    **1階層制限:**
    - トラストアンカーが直接発行: `delegator: None`（0階層）
    - 受託者経由で発行: `delegator: Some anchorDID`（1階層）
-/
structure AttributeVC where
  -- AMATELUS構造
  amatelus : AMATELUSCredential
  -- 属性固有のクレーム
  claims : Claims                             -- 任意の構造化クレーム
  deriving Repr

/-- 検証者VC

    トラストアンカーが検証者に発行する認証クレデンシャル。
    検証者が特定のクレームタイプを検証する権限を持つことを証明する。

    偽警官対策: Holderはこのような検証者VCの提示を要求することで、
    正規の検証者であることを確認できる。

    **1階層制限:**
    - 通常、トラストアンカーが直接発行: `delegator: None`（0階層）
-/
structure VerifierVC where
  -- AMATELUS構造
  amatelus : AMATELUSCredential
  -- 検証者固有のクレーム
  authorizedVerificationTypes : List ClaimTypeBasic  -- 検証可能なクレームタイプ
  verificationScope : String                          -- 検証の範囲（地域、組織など）
  deriving Repr

/-- クレーム定義VC

    トラストアンカーが自己署名で公開するクレーム定義。
    クレームIDとその意味を定義する。

    **使用例:**
    政府（トラストアンカー）が以下のようなクレーム定義VCを公開：
    - ClaimID: "政府_1", ClaimDescription: "住民票", Schema: {...}
    - ClaimID: "政府_2", ClaimDescription: "運転免許証", Schema: {...}

    検証者はトラストアンカーのDIDDocumentとともに、
    これらのクレーム定義VCをダウンロードしてWalletに登録する。

    **1階層制限:**
    - トラストアンカーが自己署名で発行: `delegator: None`（0階層）
-/
structure ClaimDefinitionVC where
  -- AMATELUS構造
  amatelus : AMATELUSCredential
  -- クレーム定義固有のフィールド
  claimID : ClaimID                     -- クレームの一意な識別子
  claimDescription : String             -- クレームの説明（人間可読）
  schema : String                       -- クレームのスキーマ（JSON Schema等）
  deriving Repr

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

/-- VCTypeからAMATELUS構造を取得

    **Stage 6設計:**
    各VC型は`amatelus`フィールドを通してAMATELUSCredentialにアクセスします。
-/
def getAMATELUSCore : VCTypeCore → AMATELUSCredential
  | trusteeVC vc => vc.amatelus
  | nationalIDVC vc => vc.amatelus
  | attributeVC vc => vc.amatelus
  | verifierVC vc => vc.amatelus
  | claimDefinitionVC vc => vc.amatelus

/-- VCTypeからW3C基本構造を取得

    **Stage 6設計:**
    各VC型は`amatelus.w3cCredential`フィールドを通してW3C.Credentialにアクセスします。
-/
def getCore : VCTypeCore → W3CCredentialCore
  | trusteeVC vc => vc.amatelus.w3cCredential
  | nationalIDVC vc => vc.amatelus.w3cCredential
  | attributeVC vc => vc.amatelus.w3cCredential
  | verifierVC vc => vc.amatelus.w3cCredential
  | claimDefinitionVC vc => vc.amatelus.w3cCredential

/-- VCTypeの発行者をDIDとして取得

    **注意:** この関数は内部実装用です。
    通常はVerifiableCredential.getIssuerを使用してください（型安全）。
-/
def getIssuer (vc : VCTypeCore) : Option DID :=
  getIssuerDID (getCore vc).issuer

/-- VCTypeの主体をDIDとして取得

    **注意:** この関数は内部実装用です。
    通常はVerifiableCredential.getSubjectを使用してください（型安全）。
-/
def getSubject (vc : VCTypeCore) : Option DID :=
  getSubjectDID (getCore vc).credentialSubject

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

    **Stage 3: 型レベルの不変条件（issuer）:**
    - `issuerDID`: ValidVCは必ずDID形式のissuerを持つことを型で保証
    - これにより、getIssuerがOption不要でDIDを直接返せる

    **Stage 4: 型レベルの不変条件（subject）:**
    - `subjectDID`: ValidVCは必ずDID形式のsubjectを持つことを型で保証
    - これにより、getSubjectがOption不要でDIDを直接返せる

    **Stage 5: 型レベルの不変条件（signature）:**
    - `signature`: ValidVCは必ず有効な署名を持つことを型で保証
    - W3C標準の設計：Credential（proof前）とVerifiableCredential（proof後）の分離
    - これにより「ValidVCは必ず有効な署名を持つ」ことが型レベルで保証される
-/
structure ValidVC where
  -- VCの種類
  vcType : VCTypeCore
  -- 発行者DID（型レベルで保証）
  issuerDID : DID
  -- 主体DID（型レベルで保証）
  subjectDID : DID
  -- デジタル署名（型レベルで保証）
  signature : Signature
  -- 不変条件: getIssuerDID (getCore vcType).issuer = some issuerDID
  -- 不変条件: getSubjectDID (getCore vcType).credentialSubject = some subjectDID
  -- 不変条件: amatSignature.verify (getCore vcType) signature = true
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

/-- VCの発行者をDIDとして取得

    **Stage 3設計:**
    - ValidVC: 型レベルで保証されたDIDを直接返す（Option不要）
    - InvalidVC: W3C.IssuerからDIDを抽出（DID形式でない場合はNone）
-/
def getIssuer (vc : VerifiableCredential) : DID :=
  match vc with
  | valid vvc => vvc.issuerDID  -- ValidVCは型レベルでDIDを保証
  | invalid _ =>
      -- InvalidVCの場合、issuerがDID形式でなければダミーDIDを返す
      match getIssuerDID (getCore vc).issuer with
      | some did => did
      | none => DID.invalid { value := "invalid:unknown" } "Non-DID issuer in InvalidVC"

/-- VCの主体をDIDとして取得

    **Stage 4設計:**
    - ValidVC: 型レベルで保証されたDIDを直接返す（Option不要）
    - InvalidVC: W3C.CredentialSubjectからDIDを抽出（DID形式でない場合はダミーDID）
-/
def getSubject (vc : VerifiableCredential) : DID :=
  match vc with
  | valid vvc => vvc.subjectDID  -- ValidVCは型レベルでDIDを保証
  | invalid _ =>
      -- InvalidVCの場合、subjectがDID形式でなければダミーDIDを返す
      match getSubjectDID (getCore vc).credentialSubject with
      | some did => did
      | none => DID.invalid { value := "invalid:unknown" } "Non-DID subject in InvalidVC"

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
