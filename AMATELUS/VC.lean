/-
# Verifiable Credential 定義

このファイルは、AMATELUSプロトコルのVerifiable Credential（検証可能資格情報）関連の型と定義を含みます。
-/

import AMATELUS.DID
import W3C.VC

-- ## Definition 2.2: Verifiable Credential

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

    W3C.IssuerのID文字列がDID形式（"did:amt:..."）の場合、DIDとして解釈します。

    **戻り値:**
    - `None`: DID形式でない、またはハッシュ情報が不明で検証できない

    **設計思想:**
    W3C VCから抽出したDIDは、DIDDocumentのハッシュ情報が不明なため、
    ValidDIDに変換できません。検証関数を使用する`getIssuerDIDWithValidation`を
    使用してください。

    **使用例:**
    - issuer: W3C.Issuer.uri "did:amt:123..." → None（ハッシュ不明）
    - issuer: W3C.Issuer.uri "https://example.com" → None（URLはDIDではない）
-/
def getIssuerDID (issuer : W3C.Issuer) : Option ValidDID :=
  let idString := issuer.getId
  -- DID形式かチェック（"did:amt:"で始まる）
  if idString.startsWith "did:amt:" then
    -- W3C.DIDとして構築
    let w3cDID : W3C.DID := { value := idString }
    -- ハッシュ情報が不明なため、InvalidDIDとして構築
    let invalidDID : InvalidDID := {
      w3cDID := w3cDID,
      reason := "Hash unknown - DID extracted from W3C VC without DIDDocument"
    }
    let unknownDID := UnknownDID.invalid invalidDID
    -- toValidDIDを通して検証（常にnoneが返る）
    UnknownDID.toValidDID unknownDID
  else
    none

/-- W3C.IssuerからDIDを取得する関数（検証付き）

    W3C.IssuerのID文字列をDIDとして解釈し、検証関数で検証します。

    **パラメータ:**
    - `issuer`: W3C.Issuer
    - `validateDID`: DID文字列を検証し、ValidDIDを返す関数（例：Wallet内のDIDリストを参照）

    **戻り値:**
    - `Some ValidDID`: 検証に成功した場合
    - `None`: DID形式でない、または検証に失敗した場合

    **使用例:**
    ```lean
    -- WalletからDIDを検証する関数
    def validateWithWallet (wallet : Wallet) (didStr : W3C.DID) : Option ValidDID :=
      wallet.identities.find? (fun id => id.did.w3cDID == didStr)
        |>.map (fun id => id.did)

    -- Issuerからvalidated DIDを取得
    let issuerDID := getIssuerDIDWithValidation issuer (validateWithWallet myWallet)
    ```
-/
def getIssuerDIDWithValidation
    (issuer : W3C.Issuer)
    (validateDID : W3C.DID → Option ValidDID) : Option ValidDID :=
  let idString := issuer.getId
  if idString.startsWith "did:amt:" then
    let w3cDID : W3C.DID := { value := idString }
    -- 検証関数を適用
    validateDID w3cDID
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
def didToW3CIssuer (did : UnknownDID) : W3C.Issuer :=
  match did with
  | UnknownDID.valid v => W3C.Issuer.uri v.w3cDID.value
  | UnknownDID.invalid i => W3C.Issuer.uri i.w3cDID.value

-- ## Helper Functions for W3C CredentialSubject

/-- W3C.CredentialSubjectからDIDを取得する関数

    W3C.CredentialSubjectのid文字列がDID形式（"did:amt:..."）の場合、DIDとして解釈します。

    **戻り値:**
    - `None`: DID形式でない、idが存在しない、またはハッシュ情報が不明で検証できない

    **設計思想:**
    W3C VCから抽出したDIDは、DIDDocumentのハッシュ情報が不明なため、
    ValidDIDに変換できません。検証関数を使用する`getSubjectDIDWithValidation`を
    使用してください。

    **使用例:**
    - credentialSubject.id = Some "did:amt:123..." → None（ハッシュ不明）
    - credentialSubject.id = Some "https://example.com" → None（URLはDIDではない）
    - credentialSubject.id = None → None
-/
def getSubjectDID (subjects : List W3C.CredentialSubject) : Option ValidDID :=
  match subjects.head? with
  | none => none
  | some subject =>
      match subject.id with
      | none => none
      | some idString =>
          -- DID形式かチェック（"did:amt:"で始まる）
          if idString.startsWith "did:amt:" then
            -- W3C.DIDとして構築
            let w3cDID : W3C.DID := { value := idString }
            -- ハッシュ情報が不明なため、InvalidDIDとして構築
            let invalidDID : InvalidDID := {
              w3cDID := w3cDID,
              reason := "Hash unknown - DID extracted from W3C VC without DIDDocument"
            }
            let unknownDID := UnknownDID.invalid invalidDID
            -- toValidDIDを通して検証（常にnoneが返る）
            UnknownDID.toValidDID unknownDID
          else
            none

/-- W3C.CredentialSubjectからDIDを取得する関数（検証付き）

    W3C.CredentialSubjectのid文字列をDIDとして解釈し、検証関数で検証します。

    **パラメータ:**
    - `subjects`: W3C.CredentialSubjectのリスト
    - `validateDID`: DID文字列を検証し、ValidDIDを返す関数

    **戻り値:**
    - `Some ValidDID`: 検証に成功した場合
    - `None`: DID形式でない、idが存在しない、または検証に失敗した場合
-/
def getSubjectDIDWithValidation
    (subjects : List W3C.CredentialSubject)
    (validateDID : W3C.DID → Option ValidDID) : Option ValidDID :=
  match subjects.head? with
  | none => none
  | some subject =>
      match subject.id with
      | none => none
      | some idString =>
          if idString.startsWith "did:amt:" then
            let w3cDID : W3C.DID := { value := idString }
            -- 検証関数を適用
            validateDID w3cDID
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
def didToCredentialSubject (did : UnknownDID) : W3C.CredentialSubject :=
  match did with
  | UnknownDID.valid v => { id := some v.w3cDID.value, claims := [] }
  | UnknownDID.invalid i => { id := some i.w3cDID.value, claims := [] }

-- ## Helper Functions for Context and VCType conversion

/-- VCの基底構造

    すべてのVC型が共通して持つフィールド。
-/
structure VCBase where
  -- W3C標準Credential構造
  w3cCredential : W3C.Credential
  -- 発行者DID（型レベルで正規のDIDを保証）
  issuerDID : ValidDID
  -- 主体DID（型レベルで正規のDIDを保証）
  subjectDID : ValidDID
  -- デジタル署名（型レベルで保証）
  signature : Signature
  -- 委任者DID（1階層制限の型システム保証）
  -- None = トラストアンカー直接発行（0階層）
  -- Some anchorDID = 委任者経由発行（1階層）
  delegator : Option ValidDID
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
structure TrusteeVC extends VCBase where
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
structure NationalIDVC extends VCBase where
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
structure AttributeVC extends VCBase where
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
structure VerifierVC extends VCBase where
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
structure ClaimDefinitionVC extends VCBase where
  -- クレーム定義固有のフィールド
  claimID : ClaimID                     -- クレームの一意な識別子
  claimDescription : String             -- クレームの説明（人間可読）
  schema : String                       -- クレームのスキーマ（JSON Schema等）
  deriving Repr

/-- 正規の検証可能資格情報 (Valid Verifiable Credential)

    署名検証が成功するVC。
    暗号学的に正しく発行されたVCは、署名検証に成功する。

    すべての具体的なVCタイプの和型。
    AMATELUSプロトコルで扱われるVCは、以下のいずれかの型を持つ：
    - TrusteeVC: 受託者認証
    - NationalIDVC: 国民識別情報
    - AttributeVC: 一般属性情報
    - VerifierVC: 検証者認証
    - ClaimDefinitionVC: クレーム定義（トラストアンカーが自己署名で公開）

    **設計思想:**
    - VCの発行はIssuerの責任（署名は暗号ライブラリで生成）
    - プロトコルレベルでは「正規に発行されたVC」として抽象化
    - Verifierは署名検証のみに依存し、Issuer実装を信頼しない

    **抽象化の利点:**
    - Ed25519署名検証などの暗号的詳細を隠蔽
    - プロトコルの安全性証明が簡潔になる
    - Issuer実装の違いを抽象化（同じプロトコルで多様なIssuer実装が可能）

    **VCBase継承:**
    - 共通フィールド（w3cCredential, issuerDID, subjectDID, signature, delegator）は
      各VC型がVCBaseを継承することで保持される
    - 各VC型は型固有のフィールドを追加で持つ
-/
inductive ValidVC
  | trusteeVC : TrusteeVC → ValidVC
  | nationalIDVC : NationalIDVC → ValidVC
  | attributeVC : AttributeVC → ValidVC
  | verifierVC : VerifierVC → ValidVC
  | claimDefinitionVC : ClaimDefinitionVC → ValidVC

namespace ValidVC

/-- ValidVCからW3C基本構造を取得 -/
def getCore : ValidVC → W3C.Credential
  | trusteeVC vc => vc.w3cCredential
  | nationalIDVC vc => vc.w3cCredential
  | attributeVC vc => vc.w3cCredential
  | verifierVC vc => vc.w3cCredential
  | claimDefinitionVC vc => vc.w3cCredential

/-- ValidVCから発行者DIDを取得 -/
def getIssuerDID : ValidVC → ValidDID
  | trusteeVC vc => vc.issuerDID
  | nationalIDVC vc => vc.issuerDID
  | attributeVC vc => vc.issuerDID
  | verifierVC vc => vc.issuerDID
  | claimDefinitionVC vc => vc.issuerDID

/-- ValidVCから主体DIDを取得 -/
def getSubjectDID : ValidVC → ValidDID
  | trusteeVC vc => vc.subjectDID
  | nationalIDVC vc => vc.subjectDID
  | attributeVC vc => vc.subjectDID
  | verifierVC vc => vc.subjectDID
  | claimDefinitionVC vc => vc.subjectDID

/-- ValidVCから署名を取得 -/
def getSignature : ValidVC → Signature
  | trusteeVC vc => vc.signature
  | nationalIDVC vc => vc.signature
  | attributeVC vc => vc.signature
  | verifierVC vc => vc.signature
  | claimDefinitionVC vc => vc.signature

/-- ValidVCから委任者を取得 -/
def getDelegator : ValidVC → Option ValidDID
  | trusteeVC vc => vc.delegator
  | nationalIDVC vc => vc.delegator
  | attributeVC vc => vc.delegator
  | verifierVC vc => vc.delegator
  | claimDefinitionVC vc => vc.delegator

end ValidVC

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
  -- W3C標準Credential構造
  w3cCredential : W3C.Credential
  -- 不正な理由（デバッグ用、プロトコルには不要）
  reason : String

/-- 未検証の資格情報 (Unknown Verifiable Credential)

    構造的に正しくパースされたVCで、署名検証の結果を表す和型。
    AMATELUSプロトコルで扱われるVCは、暗号学的に以下のいずれか：
    - valid: 正規に発行されたVC（署名検証が成功）
    - invalid: 不正なVC（署名検証が失敗）

    **命名の意図:**
    - 「UnknownVC」= 構造的にパース成功したが、署名検証の状態は未確定または既知
    - 「VerifiableCredential」から改名し、W3C標準との対応を明確化
    - W3C.Credential（proof前）とは異なり、署名検証の結果を含む

    **設計の利点:**
    - VC検証の暗号的詳細（Ed25519署名検証など）を抽象化
    - プロトコルレベルでは「正規/不正」の区別のみが重要
    - Issuer実装のバグは`invalid`として表現され、プロトコルの安全性には影響しない

    **ZKPとの設計の一貫性:**
    - ZeroKnowledgeProofと同じパターン（Valid/Invalid + 和型）
    - 統一された形式検証アプローチ
-/
inductive UnknownVC
  | valid : ValidVC → UnknownVC
  | invalid : InvalidVC → UnknownVC

namespace UnknownVC

/-- VCから基本構造を取得 -/
def getCore : UnknownVC → W3C.Credential :=
  fun vc => match vc with
  | valid vvc => ValidVC.getCore vvc
  | invalid ivc => ivc.w3cCredential

/-- VCの発行者をDIDとして取得 -/
def getIssuer (vc : UnknownVC) : UnknownDID :=
  match vc with
  | valid vvc => UnknownDID.valid (ValidVC.getIssuerDID vvc)
  | invalid _ =>
      -- InvalidVCの場合、issuerがDID形式でなければダミーDIDを返す
      -- getIssuerDIDはOption ValidDIDを返すので、UnknownDID.validに変換
      match getIssuerDID (getCore vc).issuer with
      | some did => UnknownDID.valid did
      | none => UnknownDID.invalid {
          w3cDID := { value := "invalid:unknown" },
          reason := "Non-DID issuer in InvalidVC"
        }

/-- VCの主体をDIDとして取得 -/
def getSubject (vc : UnknownVC) : UnknownDID :=
  match vc with
  | valid vvc => UnknownDID.valid (ValidVC.getSubjectDID vvc)
  | invalid _ =>
      -- InvalidVCの場合、subjectがDID形式でなければダミーDIDを返す
      -- getSubjectDIDはOption ValidDIDを返すので、UnknownDID.validに変換
      match getSubjectDID (getCore vc).credentialSubject with
      | some did => UnknownDID.valid did
      | none => UnknownDID.invalid {
          w3cDID := { value := "invalid:unknown" },
          reason := "Non-DID subject in InvalidVC"
        }

/-- VCの委任者を取得（1階層制限の検証に使用）

    **設計:**
    - ValidVC: ValidVC経由でdelegatorを取得（Option ValidDID）
    - InvalidVC: 委任者情報がないため、noneを返す
-/
def getDelegator (vc : UnknownVC) : Option ValidDID :=
  match vc with
  | valid vvc => ValidVC.getDelegator vvc
  | invalid _ => none  -- InvalidVCは委任者情報を持たない

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
def verifySignature : UnknownVC → Bool
  | valid _ => true   -- 正規のVCは常に検証成功
  | invalid _ => false -- 不正なVCは常に検証失敗

/-- VCが有効かどうかを表す述語 -/
def isValid (vc : UnknownVC) : Prop :=
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

end UnknownVC
