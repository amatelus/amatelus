/-
# Verifiable Credential 定義

このファイルは、AMATELUSプロトコルのVerifiable Credential（検証可能資格情報）関連の型と定義を含みます。
-/

import AMATELUS.DID
import AMATELUS.TrustChainTypes
import W3C.VC

-- ## Definition 2.2: Verifiable Credential

/-- クレームタイプを表す型 -/
abbrev ClaimTypeBasic := String

/-- クレーム識別子を表す型

    VC発行者が定義するクレームの一意な識別子。
    誰でもクレームを定義でき、受け取る側がどの発行者を信頼するかを決定する。
    例: "政府_1" (住民票), "政府_2" (運転免許証), "友人_1" (推薦状)
-/
structure ClaimID where
  value : String
  deriving Repr, DecidableEq, BEq

/-- クレーム（主張）を表す型

    **設計:**
    - `data`: 構造化データ（JSON等）
    - `claimID`: クレームの識別子（発行者が定義）
      - `Some claimID`: 特定のクレームタイプ（住民票、運転免許証、推薦状等）
      - `None`: クレームIDが指定されていない（汎用クレーム）

    **AHI (Anonymous Hash Identifier) について:**
    NationalID（マイナンバー等の個人番号）を含むクレームは、
    AHI機能を使用する場合にのみ `data` フィールドに含まれます。

    - **AHI機能を使用する場合:**
      - IssuerまたはVerifierが監査機能を要求する場合
      - `data` フィールドにNationalIDが含まれる
      - HolderはAHIを生成して提示する

    - **AHI機能を使用しない場合:**
      - 通常のサービス利用（監査不要）
      - `data` フィールドにNationalIDは含まれない
      - 通常のVCとZKPのみで運用される

    **重要:** 個人番号制度がない国でも、NationalIDを含まないVCで
    AMATELUSプロトコルは完全に機能します。
-/
structure Claims where
  data : String  -- 実際には構造化データ（NationalIDはオプショナル）
  claimID : Option ClaimID  -- クレームの識別子（オプショナル）
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

    AHI := H(AuditSectionID || NationalID)

    **オプショナル機能:**
    AHIはAMATELUSプロトコルのオプショナル機能です。
    使用するかどうかは、IssuerまたはVerifierが決定します。

    - **AHIが使用される場合:**
      - 監査が必要なサービス（納税、給付、許認可等）
      - 多重アカウント防止が必要なサービス（SNS、チケット販売等）
      - 個人番号制度が存在する国・地域

    - **AHIが使用されない場合:**
      - 通常のサービス利用（監査不要）
      - 個人番号制度がない国・地域
      - Holderが任意にAHIの提示を拒否することも可能

    **設計の重要な性質:**
    - `ProtocolState.ahis: List` は空リスト `[]` でも良い
    - AHI機能を使用しなくても、AMATELUSは完全に機能する
    - NationalIDSystemが存在しない場合、AHIは構築できない
-/
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
    AMATELUSでは、claimsはValidVC.claimsフィールドに保存されます。
    W3C.CredentialSubject.claimsはAMATELUSでは使用しません。
-/
def didToCredentialSubject (did : UnknownDID) : W3C.CredentialSubject :=
  match did with
  | UnknownDID.valid v => { id := some v.w3cDID.value, claims := [] }
  | UnknownDID.invalid i => { id := some i.w3cDID.value, claims := [] }

-- ## Helper Functions for Context and VCType conversion

/-- 正規の検証可能資格情報 (Valid Verifiable Credential)

    署名検証が成功するVC。
    暗号学的に正しく発行されたVCは、署名検証に成功する。

    一般的な属性情報（年齢、住所、資格など）を証明するVC。
    汎用的なクレームタイプで、様々な発行者が発行できる。

    **設計の簡素化:**
    - すべての属性情報（検証者資格含む）を単一の型で表現
    - w3cCredential.credentialSubject.claimsに委任チェーンを埋め込むことで、受託者認証として機能
    - 各Walletの所有者が、どのDIDを信頼するか（Wallet.trustedAnchorsに登録）を自由に決定

    **階層制限（N階層対応）:**
    - 直接発行: claims配列に委任チェーンなし（0階層）
    - N階層委譲発行: claims配列にDelegationChainを含む（N階層）
      - DelegationChainにより複数階層の委任を表現
      - 各delegationのmaxDepthにより階層制限を動的に設定
      - 循環委任をDID重複チェックで防止
      - 詳細はTrustChain.mdとTrustChainTypes.leanを参照

    **使用例:**
    自治体Aが政府から委譲された権限で住民票VCを発行する場合、
    w3cCredential.credentialSubject.claimsには委任チェーン（DelegationChain）が含まれる。
    詳細はTrustChainTypes.leanのDelegationChain型を参照。

    **設計思想:**
    - VCの発行はIssuerの責任（署名は暗号ライブラリで生成）
    - プロトコルレベルでは「正規に発行されたVC」として抽象化
    - Verifierは署名検証のみに依存し、Issuer実装を信頼しない

    **抽象化の利点:**
    - Ed25519署名検証などの暗号的詳細を隠蔽
    - プロトコルの安全性証明が簡潔になる
    - Issuer実装の違いを抽象化（同じプロトコルで多様なIssuer実装が可能）

    **フィールド構成:**
    - w3cCredential: W3C標準Credential構造
    - issuerDID: 発行者DID（型レベルで正規のDIDを保証）
    - subjectDID: 主体DID（型レベルで正規のDIDを保証）
    - signature: デジタル署名（型レベルで保証）
    - claims: 属性固有のクレーム（任意の構造化クレーム）

    **権限証明の埋め込み方法:**
    委譲された権限で発行するVCでは、W3C.Credential.credentialSubject.claimsに以下を含める：
    1. 主体の属性情報（本来のクレームデータ）
    2. DelegationChain（N階層の委任チェーン）

    これにより、VCが自己完結し、別VCの提示が不要になる。
-/
structure ValidVC where
  -- W3C標準Credential構造
  w3cCredential : W3C.Credential
  -- 発行者DID（型レベルで正規のDIDを保証）
  issuerDID : ValidDID
  -- 主体DID（型レベルで正規のDIDを保証）
  subjectDID : ValidDID
  -- デジタル署名（型レベルで保証）
  signature : Signature
  -- 属性固有のクレーム
  claims : Claims
  deriving Repr

namespace ValidVC

/-- ValidVCから委任チェーンを取得

    w3cCredential.credentialSubject.claimsから委任チェーン（DelegationChain）を抽出する。

    **戻り値:**
    - `Some chain`: 委任チェーンが見つかった場合（N階層委譲発行）
    - `None`: 委任チェーンがない場合（直接発行）

    **使用例:**
    ```lean
    match getDelegationChain vc with
    | none => -- 直接発行VC
    | some chain =>
        -- N階層委譲発行VC
        -- chain.depthで階層数を取得
        -- chain.verifyで委任チェーンを検証
    ```
-/
def getDelegationChain (_vc : ValidVC) : Option DelegationChain :=
  -- TODO: W3C.CredentialSubject.claimsからDelegationChainを抽出する実装
  -- 現時点では、データ構造の定義のみを提供
  none

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

/-- VCの発行者をDIDとして取得 -/
def getIssuer (vc : UnknownVC) : UnknownDID :=
  match vc with
  | valid vvc => UnknownDID.valid vvc.issuerDID
  | invalid ivc =>
      -- InvalidVCの場合、issuerがDID形式でなければダミーDIDを返す
      -- getIssuerDIDはOption ValidDIDを返すので、UnknownDID.validに変換
      match getIssuerDID ivc.w3cCredential.issuer with
      | some did => UnknownDID.valid did
      | none => UnknownDID.invalid {
          w3cDID := { value := "invalid:unknown" },
          reason := "Non-DID issuer in InvalidVC"
        }

/-- VCの主体をDIDとして取得 -/
def getSubject (vc : UnknownVC) : UnknownDID :=
  match vc with
  | valid vvc => UnknownDID.valid vvc.subjectDID
  | invalid ivc =>
      -- InvalidVCの場合、subjectがDID形式でなければダミーDIDを返す
      -- getSubjectDIDはOption ValidDIDを返すので、UnknownDID.validに変換
      match getSubjectDID ivc.w3cCredential.credentialSubject with
      | some did => UnknownDID.valid did
      | none => UnknownDID.invalid {
          w3cDID := { value := "invalid:unknown" },
          reason := "Non-DID subject in InvalidVC"
        }

/-- VCから委任チェーンを取得

    w3cCredential.credentialSubject.claimsから委任チェーン（DelegationChain）を抽出する。

    **戻り値:**
    - `Some chain`: 委任チェーンが見つかった場合（N階層委譲発行）
    - `None`: 委任チェーンがない場合（直接発行）、またはInvalidVC
-/
def getDelegationChain (vc : UnknownVC) : Option DelegationChain :=
  match vc with
  | valid vvc => ValidVC.getDelegationChain vvc
  | invalid _ => none  -- InvalidVCは委任チェーン情報を持たない

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
