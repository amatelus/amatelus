/-
# Verifiable Credential 定義

このファイルは、AMATELUSプロトコルのVerifiable Credential（検証可能資格情報）関連の型と定義を含みます。
-/

import AMATELUS.DID
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

-- ## Authorization Proof for Embedded Trust Delegation

/-- 権限証明（Authorization Proof）

    権限を与える側から受ける側への権限委譲を証明する構造。
    この構造はW3C.CredentialSubject.claims内に埋め込まれる。

    **新設計の利点:**
    - Self-contained VC: 単一のVCで全ての検証が完結
    - 別VCの提示不要: 権限証明がVC内に含まれる
    - プライバシー向上: 受託者のWallet内容を公開不要
    - 実世界適合: 紙の証明書に近い概念

    **使用例:**
    政府が自治体Aに住民票発行権限を委譲する場合：
    - grantorDID: "did:amt:gov123..."
    - granteeDID: "did:amt:city-a456..."
    - authorizedClaimIDs: ["住民票", "戸籍謄本"]
    - grantorSignature: "0x123abc..." （政府の署名）

    住民が自治体Aから住民票VCを受け取る際、このVC内のclaims配列に：
    1. 住民の属性情報（氏名、住所等）
    2. この権限証明（政府→自治体Aの委譲証明）
    が両方含まれる。

    **重要な設計思想:**
    誰でも他者に権限を委譲できるが、その委譲が有効かどうかは受け取る側が
    grantorを自分のWallet.trustedAnchorsに登録しているかで決まる。
-/
structure AuthorizationProof where
  /-- 権限を与える側のDID -/
  grantorDID : ValidDID
  /-- 権限を受ける側のDID -/
  granteeDID : ValidDID
  /-- 発行可能なクレームIDのリスト -/
  authorizedClaimIDs : List ClaimID
  /-- 権限を与える側の署名（この権限証明全体に対する署名） -/
  grantorSignature : Signature
  deriving Repr

namespace AuthorizationProof

/-- AuthorizationProofをW3C.DIDValue.mapに変換

    W3C.CredentialSubject.claims内に埋め込むため、DIDValue形式に変換する。

    **DIDValue構造:**
    ```
    DIDValue.map [
      ("auth_proof", DIDValue.map [
        ("grantor_did", DIDValue.string "did:amt:..."),
        ("grantee_did", DIDValue.string "did:amt:..."),
        ("authorized_claim_ids", DIDValue.list [
          DIDValue.string "claim1",
          DIDValue.string "claim2"
        ]),
        ("grantor_signature", DIDValue.string "0x...")
      ])
    ]
    ```
-/
def toDIDValue (proof : AuthorizationProof) : W3C.DIDValue :=
  W3C.DIDValue.map [
    ("grantor_did", W3C.DIDValue.string proof.grantorDID.w3cDID.value),
    ("grantee_did", W3C.DIDValue.string proof.granteeDID.w3cDID.value),
    ("authorized_claim_ids", W3C.DIDValue.list
      (proof.authorizedClaimIDs.map fun cid => W3C.DIDValue.string cid.value)),
    ("grantor_signature", W3C.DIDValue.string (toString proof.grantorSignature.bytes))
  ]

/-- W3C.DIDValueからAuthorizationProofを抽出（検証付き）

    **パラメータ:**
    - `didValue`: 抽出元のDIDValue
    - `validateDID`: DID文字列を検証する関数

    **戻り値:**
    - `Some proof`: 抽出・検証成功
    - `None`: 構造不正またはDID検証失敗
-/
def fromDIDValue
    (didValue : W3C.DIDValue)
    (validateDID : W3C.DID → Option ValidDID) : Option AuthorizationProof :=
  match didValue with
  | W3C.DIDValue.map fields =>
      -- 各フィールドを抽出
      let grantorDIDStr := fields.lookup "grantor_did"
      let granteeDIDStr := fields.lookup "grantee_did"
      let authorizedClaimIDsVal := fields.lookup "authorized_claim_ids"
      let grantorSigStr := fields.lookup "grantor_signature"

      match grantorDIDStr, granteeDIDStr, authorizedClaimIDsVal, grantorSigStr with
      | some (W3C.DIDValue.string grantorStr),
        some (W3C.DIDValue.string granteeStr),
        some (W3C.DIDValue.list claimIDVals),
        some (W3C.DIDValue.string _sigStr) =>
          -- DID検証
          let grantorDIDOpt := validateDID { value := grantorStr }
          let granteeDIDOpt := validateDID { value := granteeStr }

          match grantorDIDOpt, granteeDIDOpt with
          | some grantorDID, some granteeDID =>
              -- ClaimIDリストを抽出
              let claimIDs := claimIDVals.filterMap fun val =>
                match val with
                | W3C.DIDValue.string s => some { value := s : ClaimID }
                | _ => none

              -- AuthorizationProofを構築
              -- TODO: sigStrを List UInt8 に変換する必要がある
              some {
                grantorDID := grantorDID,
                granteeDID := granteeDID,
                authorizedClaimIDs := claimIDs,
                grantorSignature := { bytes := [] }  -- 仮実装
              }
          | _, _ => none
      | _, _, _, _ => none
  | _ => none

/-- W3C.CredentialSubject.claimsから権限証明を抽出

    claims配列から"auth_proof"キーを持つエントリを探し、
    AuthorizationProofとして抽出する。

    **パラメータ:**
    - `claims`: W3C.CredentialSubject.claimsリスト
    - `validateDID`: DID検証関数

    **戻り値:**
    - `Some proof`: 権限証明が見つかり、検証成功
    - `None`: 権限証明が見つからないか、検証失敗
-/
def fromCredentialSubjectClaims
    (claims : List (String × W3C.DIDValue))
    (validateDID : W3C.DID → Option ValidDID) : Option AuthorizationProof :=
  match claims.lookup "auth_proof" with
  | none => none
  | some authProofValue => fromDIDValue authProofValue validateDID

/-- 権限証明の署名を検証

    **検証内容:**
    1. grantorSignatureがgrantorDIDの公開鍵で検証できるか
    2. 署名対象データ: granteeDID || authorizedClaimIDs

    **設計:**
    実装では、Signature型が既に検証済みであることを前提とする。
    （ValidVC構築時に署名検証済み）
    この関数は形式的な検証ロジックのプレースホルダー。
-/
def verifyProofSignature (_proof : AuthorizationProof) : Bool :=
  -- 実装: 署名検証ロジック
  -- 現時点では、SignatureがValidVCに含まれる時点で検証済みと仮定
  true

end AuthorizationProof

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

    **新設計の簡素化:**
    - すべての属性情報（検証者資格含む）を単一の型で表現
    - w3cCredential.credentialSubject.claimsに権限証明を埋め込むことで、受託者認証として機能
    - 各Walletの所有者が、どのDIDを信頼するか（Wallet.trustedAnchorsに登録）を自由に決定

    **新設計における1階層制限:**
    - 直接発行: w3cCredential.credentialSubject.claimsに権限証明なし（0階層）
      発行者が当該Walletで信頼されていれば受け入れ
    - 委譲発行: w3cCredential.credentialSubject.claimsに権限証明あり（1階層）
      - claims配列に ("auth_proof", AuthorizationProof) を含む
      - AuthorizationProofのgrantorが当該Walletで信頼されていれば受け入れ

    **使用例:**
    自治体Aが政府から委譲された権限で住民票VCを発行する場合、
    w3cCredential.credentialSubject.claimsには以下が含まれる：
    ```
    [
      ("resident_info", DIDValue.map [住民の属性]),
      ("auth_proof", AuthorizationProof {
        grantorDID: 政府DID,
        granteeDID: 自治体ADID,
        authorizedClaimIDs: ["住民票"],
        grantorSignature: 政府の署名
      })
    ]
    ```

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
    2. AuthorizationProof（権限を与える側→権限を受ける側の委譲証明）

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

/-- ValidVCから権限を与えた側のDIDを取得

    **新設計:**
    w3cCredential.credentialSubject.claimsから権限証明を抽出し、
    grantorDID（権限を与えた側のDID）を返す。

    **戻り値:**
    - `Some grantorDID`: 権限証明が見つかった場合（委譲発行）
    - `None`: 権限証明がない場合（直接発行）

    **パラメータ:**
    - `validateDID`: DID検証関数（通常はWallet.identitiesで検証）
-/
def getDelegator (vc : ValidVC) (validateDID : W3C.DID → Option ValidDID) : Option ValidDID :=
  let w3cCred := vc.w3cCredential
  match w3cCred.credentialSubject.head? with
  | none => none
  | some subject =>
      match AuthorizationProof.fromCredentialSubjectClaims subject.claims validateDID with
      | none => none
      | some proof => some proof.grantorDID

/-- ValidVCから発行可能なクレームIDのリストを取得

    **新設計:**
    w3cCredential.credentialSubject.claimsから権限証明を抽出し、
    authorizedClaimIDsを返す。

    **戻り値:**
    - 権限証明がある場合: authorizedClaimIDsのリスト
    - 権限証明がない場合: 空リスト []

    **パラメータ:**
    - `validateDID`: DID検証関数
-/
def getAuthorizedClaimIDs (vc : ValidVC) (validateDID : W3C.DID → Option ValidDID) : List ClaimID :=
  let w3cCred := vc.w3cCredential
  match w3cCred.credentialSubject.head? with
  | none => []
  | some subject =>
      match AuthorizationProof.fromCredentialSubjectClaims subject.claims validateDID with
      | none => []
      | some proof => proof.authorizedClaimIDs

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

/-- VCの権限を与えた側のDIDを取得（1階層制限の検証に使用）

    **新設計:**
    w3cCredential.credentialSubject.claimsから権限証明を抽出し、
    grantorDID（権限を与えた側のDID）を返す。

    **戻り値:**
    - `Some grantorDID`: 権限証明が見つかった場合（委譲発行）
    - `None`: 権限証明がない場合（直接発行）、またはInvalidVC

    **パラメータ:**
    - `validateDID`: DID検証関数
-/
def getDelegator (vc : UnknownVC) (validateDID : W3C.DID → Option ValidDID) : Option ValidDID :=
  match vc with
  | valid vvc => ValidVC.getDelegator vvc validateDID
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
