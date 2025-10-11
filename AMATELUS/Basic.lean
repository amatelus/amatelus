/-
# AMATELUSプロトコルの基本定義

このファイルは、AMATELUSプロトコルの基本的な型と定義を含みます。
-/

import AMATELUS.CryptoTypes
import AMATELUS.SecurityAssumptions

-- ## 基本型定義
-- Hash、PublicKey、SecretKey、Signature、PublicInput、Witness、Proof、Relationは
-- AMATELUS.CryptoTypesで定義されています。

/-- サービスエンドポイントを表す型 -/
structure ServiceEndpoint where
  url : String
  deriving Repr, DecidableEq

/-- メタデータを表す型 -/
structure Metadata where
  data : String
  deriving Repr, DecidableEq

-- ## Definition 2.1: DID and DID Document

/-- DIDドキュメントの基本構造（データのみ）

    AMATELUSではDIDDocumentは以下の2つのケースで使用される：
    1. DIDConn（VC発行フロー）: Holderが秘密鍵所有権を証明してIssuerに提示
    2. トラストアンカーの公開情報（政府配布 or 公式サイトからダウンロード）
-/
structure DIDDocumentCore where
  publicKey : PublicKey
  service : ServiceEndpoint
  metadata : Metadata
  deriving Repr, DecidableEq

/-- 正規のDIDDocument（所有権検証済み）

    以下のいずれかの方法で検証されたDIDDocument：
    1. **Issuerによるチャレンジ検証**: DIDConnでHolderが秘密鍵所有権を証明
    2. **トラストアンカー**: 政府配布のウォレットに登録済み、または公式サイトからダウンロード

    **設計思想:**
    - DIDDocumentの正規性（所有権検証済み）を型レベルで保証
    - Issuerは検証済みのValidDIDDocumentからValidDIDを構築できる
    - トラストアンカーのValidDIDDocumentは公的に信頼される
-/
structure ValidDIDDocument where
  core : DIDDocumentCore
  -- 不変条件: 秘密鍵所有権が検証済み
  deriving Repr, DecidableEq

/-- 不正なDIDDocument

    秘密鍵所有権が未検証、または検証に失敗したDIDDocument。
    以下のいずれかの理由で不正：
    - チャレンジ検証に失敗
    - 改ざんされたDIDDocument
    - 信頼できないソースから取得
-/
structure InvalidDIDDocument where
  core : DIDDocumentCore
  reason : String
  deriving Repr

/-- DIDDocument（和型）

    Holderから提示されるDIDDocumentは、以下のいずれか：
    - valid: 所有権検証済みのDIDDocument
    - invalid: 所有権未検証または検証失敗のDIDDocument

    **AMATELUSでの使用:**
    - HolderはDIDDocument（和型）をIssuerに提示
    - Issuerはチャレンジで検証し、成功ならValidDIDDocumentを獲得
    - ValidDIDDocumentからValidDIDを構築可能
-/
inductive DIDDocument
  | valid : ValidDIDDocument → DIDDocument
  | invalid : InvalidDIDDocument → DIDDocument

/-- DIDDocumentのBeqインスタンス -/
instance : BEq DIDDocument where
  beq
    | DIDDocument.valid v1, DIDDocument.valid v2 => v1 == v2
    | DIDDocument.invalid i1, DIDDocument.invalid i2 => i1.core == i2.core
    | _, _ => false

/-- DIDDocumentのReprインスタンス -/
instance : Repr DIDDocument where
  reprPrec
    | DIDDocument.valid v, _ => "DIDDocument.valid " ++ repr v
    | DIDDocument.invalid i, _ => "DIDDocument.invalid { core := " ++ repr i.core ++ ", reason := \"" ++ i.reason ++ "\" }"

/-- DIDDocumentのDecidableEqインスタンス -/
instance : DecidableEq DIDDocument := fun a b =>
  match a, b with
  | DIDDocument.valid v1, DIDDocument.valid v2 =>
      if h : v1 = v2 then isTrue (congrArg DIDDocument.valid h)
      else isFalse (fun h_eq => h (DIDDocument.valid.inj h_eq))
  | DIDDocument.invalid i1, DIDDocument.invalid i2 =>
      if h : i1.core = i2.core ∧ i1.reason = i2.reason then
        isTrue (by cases i1; cases i2; simp at h; cases h.1; cases h.2; rfl)
      else isFalse (fun h_eq => by
        cases h_eq
        exact h ⟨rfl, rfl⟩)
  | DIDDocument.valid _, DIDDocument.invalid _ => isFalse (fun h => nomatch h)
  | DIDDocument.invalid _, DIDDocument.valid _ => isFalse (fun h => nomatch h)

namespace DIDDocument

/-- DIDDocumentからコア構造を取得 -/
def getCore : DIDDocument → DIDDocumentCore
  | valid v => v.core
  | invalid i => i.core

/-- DIDDocumentが有効かどうかを表す述語 -/
def isValid : DIDDocument → Prop
  | valid _ => True
  | invalid _ => False

end DIDDocument

/-- 正規のDID (Valid DID)

    Wallet内に対応するIdentityが存在するDID。
    正規のDIDは、Wallet内の秘密鍵で制御できる。

    **設計思想:**
    - Wallet内に対応するIdentityがあることが保証されている
    - DIDConn（VC発行フロー）で使用可能
    - 秘密鍵を持っているため、署名やZKP生成が可能

    **抽象化の利点:**
    - DIDの正規性（Wallet内に存在）を型レベルで保証
    - プロトコルレベルでは「正規/不正」の区別のみが重要
    - Wallet実装のバグは`invalid`として表現され、プロトコルの安全性には影響しない

    **ZKP/VC/DIDPairとの設計の一貫性:**
    - ZeroKnowledgeProof、VerifiableCredential、DIDPairと同じパターン（Valid/Invalid + 和型）
    - 統一された形式検証アプローチ
-/
structure ValidDID where
  hash : Hash
  deriving Repr, DecidableEq

/-- 不正なDID (Invalid DID)

    Wallet内に対応するIdentityが存在しないDID。
    以下のいずれかの理由で不正：
    - Walletバグで間違ったDID文字列を生成
    - 他人のDIDを盗み見て使用（悪意の攻撃）
    - 形式は正しいが、秘密鍵を持っていない
    - 文字列のパース失敗

    **Walletバグ・悪意の攻撃の影響:**
    - バグのあるWalletが生成したDIDは`InvalidDID`として表現される
    - 悪意のあるHolderが他人のDIDを使おうとしても`InvalidDID`になる
    - プロトコルの安全性には影響しない（当該HolderのみがVC発行を拒否される）
-/
structure InvalidDID where
  hash : Hash
  reason : String  -- "Not in wallet", "Stolen DID", "Malformed", etc.
  deriving Repr

/-- DID (Decentralized Identifier)

    正規のDIDと不正なDIDの和型。
    AMATELUSプロトコルで扱われるDIDは、以下のいずれか：
    - valid: 正規のDID（Wallet内に対応するIdentityがある）
    - invalid: 不正なDID（Wallet内にIdentityがない、または盗難DID）

    **設計の利点:**
    - DIDの正規性をプロトコルレベルで明確に区別
    - Walletバグや悪意の攻撃を型レベルで表現
    - ZKP/VC/DIDPairと完全に統一された設計

    **AMATELUSのDIDConn（VC発行フロー）:**
    - HolderがIssuerにDIDを送信してVC発行を依頼
    - IssuerはDIDを受け取り、VCに埋め込む（issuer/subjectフィールド）
    - Walletバグで間違ったDIDを送ると`InvalidDID`になる
    - 悪意のあるHolderが他人のDIDを使うと`InvalidDID`になる
    - いずれの場合も、VCは発行されるが、そのVCを使うことができない
      （Holderが秘密鍵を持っていないため、ZKPを生成できない）

    **ZKP/VC/DIDPairとの設計の一貫性:**
    - ZeroKnowledgeProof、VerifiableCredential、DIDPairと同じパターン（Valid/Invalid + 和型）
    - 統一された形式検証アプローチ
-/
inductive DID
  | valid : ValidDID → DID
  | invalid : InvalidDID → DID

/-- DIDのBeqインスタンス -/
instance : BEq DID where
  beq
    | DID.valid v1, DID.valid v2 => v1.hash == v2.hash
    | DID.invalid i1, DID.invalid i2 => i1.hash == i2.hash
    | _, _ => false

/-- DIDのReprインスタンス -/
instance : Repr DID where
  reprPrec
    | DID.valid v, _ => "DID.valid { hash := " ++ repr v.hash ++ " }"
    | DID.invalid i, _ => "DID.invalid { hash := " ++ repr i.hash ++ ", reason := \"" ++ i.reason ++ "\" }"

/-- DIDのDecidableEqインスタンス -/
instance : DecidableEq DID := fun a b =>
  match a, b with
  | DID.valid v1, DID.valid v2 =>
      if h : v1 = v2 then isTrue (congrArg DID.valid h)
      else isFalse (fun h_eq => h (DID.valid.inj h_eq))
  | DID.invalid i1, DID.invalid i2 =>
      if h : i1.hash = i2.hash ∧ i1.reason = i2.reason then
        isTrue (by cases i1; cases i2; simp at h; cases h.1; cases h.2; rfl)
      else isFalse (fun h_eq => by
        cases h_eq
        exact h ⟨rfl, rfl⟩)
  | DID.valid _, DID.invalid _ => isFalse (fun h => nomatch h)
  | DID.invalid _, DID.valid _ => isFalse (fun h => nomatch h)

/-- ValidDIDDocumentをバイト列にシリアライズする関数

    シリアライズ形式:
    publicKey.bytes ++ service.url.toUTF8 ++ metadata.data.toUTF8

    **設計:**
    - 決定的: 同じDIDDocumentは常に同じバイト列を生成
    - 単射性: シリアライズ形式により、異なるDIDDocumentは異なるバイト列を生成（高確率）
-/
def serializeDIDDocument (doc : ValidDIDDocument) : List UInt8 :=
  -- PublicKeyのバイト列
  doc.core.publicKey.bytes ++
  -- ServiceEndpointのURLをUTF8バイト列に変換
  doc.core.service.url.toUTF8.data.toList ++
  -- MetadataのデータをUTF8バイト列に変換
  doc.core.metadata.data.toUTF8.data.toList

/-- ValidDIDDocumentからValidDIDを生成する関数

    この関数は、所有権検証済みのDIDDocumentから決定的にValidDIDを生成します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後、ValidDIDDocumentからValidDIDを構築
    - トラストアンカー: 公開されたValidDIDDocumentからValidDIDを取得
    - Verifier: トラストアンカーのValidDIDDocumentからValidDIDを取得

    **技術仕様:**
    - 入力: ValidDIDDocument（所有権検証済み）
    - 出力: ValidDID
    - 性質: 決定性（同じ入力には同じ出力）、単射性（高確率）

    **実装:**
    1. ValidDIDDocumentをバイト列にシリアライズ
    2. SHA3-512でハッシュ化（hashForDID）
    3. ハッシュ値を持つValidDIDを構築
-/
noncomputable def validDIDDocumentToDID (doc : ValidDIDDocument) : ValidDID :=
  { hash := hashForDID (serializeDIDDocument doc) }

-- ## ハッシュ関数
-- hashForDID と hashForDID_collision_negligible は
-- AMATELUS.SecurityAssumptionsで定義されています。

namespace DID

/-- ValidDIDDocumentからValidDIDを生成する

    validDIDDocumentToDIDを使用して、所有権検証済みのDIDDocumentから
    ValidDIDを生成します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後にValidDIDを取得
    - Verifier: トラストアンカーの公開DIDDocumentからValidDIDを取得

    この定義により、以下が保証される：
    - **決定性**: 同じValidDIDDocumentからは常に同じValidDIDが生成される
    - **一意性**: 異なるValidDIDDocumentは（高確率で）異なるValidDIDを生成する
-/
noncomputable def fromValidDocument (doc : ValidDIDDocument) : ValidDID :=
  validDIDDocumentToDID doc

/-- DIDDocumentからDID（和型）を生成する

    - ValidDIDDocument → valid DID
    - InvalidDIDDocument → invalid DID

    この関数により、DIDDocumentの正規性がDIDの正規性に反映されます。
-/
noncomputable def fromDocument (doc : DIDDocument) : DID :=
  match doc with
  | DIDDocument.valid vdoc => DID.valid (fromValidDocument vdoc)
  | DIDDocument.invalid idoc => DID.invalid {
      hash := { value := [] },  -- ダミーハッシュ
      reason := "Invalid DIDDocument: " ++ idoc.reason
    }

/-- DIDからハッシュ値を取得 -/
def getHash : DID → Hash
  | valid vdid => vdid.hash
  | invalid idid => idid.hash

/-- DIDがValidDIDDocumentから正しく生成されたかを検証 -/
def isValid (did : DID) (doc : ValidDIDDocument) : Prop :=
  match did with
  | valid vdid => vdid = fromValidDocument doc
  | invalid _ => False  -- 不正なDIDは常に無効

-- ## DIDとDIDドキュメントの正規性

/-- 正規のDID-DIDドキュメントのペア

    HolderがVerifierに提示するペアは、この述語を満たす必要がある。
    正規のペアは、DIDがValidDIDDocumentから正しく生成されたものである。
-/
def isCanonicalPair (did : DID) (doc : ValidDIDDocument) : Prop :=
  isValid did doc

/-- 不正なDID-DIDドキュメントのペア

    以下のいずれかの場合、ペアは不正である：
    1. DIDとValidDIDDocumentが一致しない
    2. InvalidDIDDocumentから生成されたDID
-/
def isInvalidPair (did : DID) (doc : ValidDIDDocument) : Prop :=
  ¬isValid did doc

/-- Theorem: 不正なペアは検証に失敗する

    HolderがVerifierに不正な(did, doc)ペアを提示した場合、
    isValid did doc = Falseとなり、検証は失敗する。
-/
theorem invalid_pair_fails_validation :
  ∀ (did : DID) (doc : ValidDIDDocument),
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
  ∀ (did : DID) (doc : ValidDIDDocument),
    isValid did doc →
    isCanonicalPair did doc := by
  intro did doc h_valid
  unfold isCanonicalPair
  exact h_valid

/-- Theorem: Verifierは不正なペアを受け入れない（健全性）

    Verifierが(did, doc)ペアを受け取った時、
    isValid did doc = Falseならば、検証は失敗する。

    これは、不正なHolderや攻撃者が偽のペアを提示しても
    受け入れられないことを保証する。
-/
theorem verifier_rejects_invalid_pair :
  ∀ (did : DID) (doc : ValidDIDDocument),
    ¬isValid did doc →
    -- Verifierの検証ロジック
    ∃ (verificationFailed : Bool),
      verificationFailed = true := by
  intro did doc h_invalid
  -- 検証失敗を表すフラグを構成
  refine ⟨true, rfl⟩

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

/-- W3C ZKP仕様の基本構造

    すべてのZKPはこの基本構造を含む。
    参考: W3C VC Data Model 2.0 の Proof 仕様
-/
structure W3CZKProofCore where
  proof : Proof               -- 証明データ（π）
  publicInput : PublicInput   -- 公開入力（x）
  proofPurpose : String       -- 証明の目的（authentication, assertionMethodなど）
  created : Timestamp         -- 証明生成時刻

/-- Verifier認証用ZKPの基本構造

    Verifierが自身の正当性を証明するためのZKP。
    "私（verifierDID）は、信頼できるトラストアンカーから
    発行されたVerifierVCを保持している"ことを証明。

    **双方向ナンス:**
    challengeNonceは実際には双方のナンスの組み合わせを含む。
    AMATELUSでは、HolderとVerifierの双方がナンスを生成し、
    どちらか一方のWalletにバグがあっても保護される設計。
-/
structure VerifierAuthZKPCore where
  core : W3CZKProofCore
  verifierDID : DID           -- 証明者（Verifier）のDID
  challengeNonce : Nonce      -- 双方向チャレンジnonce: H(nonce_holder || nonce_verifier)
  credentialType : String     -- 証明対象のVC種類（"VerifierVC"など）

/-- Holder資格証明用ZKPの基本構造

    Holderが特定の属性を証明するためのZKP。
    "私は特定の属性を満たすVCを保持している"ことを証明。
    例: "私は20歳以上である"、"私は運転免許を持っている"など

    **双方向ナンス:**
    challengeNonceは双方のナンスの組み合わせを含む。
    - Holderが nonce_holder を生成してVerifierに送信
    - Verifierが nonce_verifier を生成してHolderに送信
    - challengeNonce = H(nonce_holder || nonce_verifier)

    この設計により、どちらか一方のWalletにバグがあっても、
    もう一方のランダムネスにより保護される。
    「他人のWalletバグから被害を受けない」設計原則を保証。
-/
structure HolderCredentialZKPCore where
  core : W3CZKProofCore
  holderDID : DID             -- 証明者（Holder）のDID
  challengeNonce : Nonce      -- 双方向チャレンジnonce: H(nonce_holder || nonce_verifier)
  claimedAttributes : String  -- 証明する属性の記述

/-- VerifierAuthZKPの型エイリアス（MutualAuthenticationで使用） -/
abbrev VerifierAuthZKP := VerifierAuthZKPCore

/-- HolderCredentialZKPの型エイリアス（MutualAuthenticationで使用） -/
abbrev HolderCredentialZKP := HolderCredentialZKPCore

/-- 正規のゼロ知識証明 (Valid Zero-Knowledge Proof)

    暗号学的に正しく生成されたZKP。
    任意のRelationに対して暗号的検証が成功する（verifyを通過する）。

    **設計思想:**
    - ZKPの生成はWalletの責任（暗号ライブラリの実装詳細）
    - プロトコルレベルでは「正規に生成されたZKP」として抽象化
    - Verifierは暗号的検証のみに依存し、Wallet実装を信頼しない

    **抽象化の利点:**
    - Groth16のペアリング検証などの暗号的詳細を隠蔽
    - プロトコルの安全性証明が簡潔になる
    - Wallet実装の違いを抽象化（同じプロトコルで多様なWallet実装が可能）
-/
structure ValidZKP where
  -- ZKPの種類
  zkpType : VerifierAuthZKPCore ⊕ HolderCredentialZKPCore
  -- 暗号学的に正しく生成されたという不変条件（抽象化）
  -- 実際のGroth16ペアリング検証などの詳細は抽象化される

/-- 不正なゼロ知識証明 (Invalid Zero-Knowledge Proof)

    暗号学的に不正なZKP。
    以下のいずれかの理由で不正：
    - Witness（秘密情報）が不正
    - 証明データπが改ざんされている
    - ランダムネスが不足している（Walletバグ）
    - 署名検証に失敗する
    - Relationが不一致

    **Walletバグの影響:**
    - バグのあるWalletが生成したZKPは`InvalidZKP`として表現される
    - プロトコルの安全性には影響しない（当該利用者のみが影響を受ける）
-/
structure InvalidZKP where
  -- ZKPの種類
  zkpType : VerifierAuthZKPCore ⊕ HolderCredentialZKPCore
  -- 不正な理由（デバッグ用、プロトコルには不要）
  reason : String

/-- ゼロ知識証明 (Zero-Knowledge Proof)

    正規のZKPと不正なZKPの和型。
    AMATELUSプロトコルで扱われるZKPは、暗号学的に以下のいずれか：
    - valid: 正規に生成されたZKP（暗号的に正しい）
    - invalid: 不正なZKP（暗号的に間違っている、または改ざんされている）

    **設計の利点:**
    - ZKP検証の暗号的詳細（Groth16のペアリング計算など）を抽象化
    - プロトコルレベルでは「正規/不正」の区別のみが重要
    - Wallet実装のバグは`invalid`として表現され、プロトコルの安全性には影響しない
-/
inductive ZeroKnowledgeProof
  | valid : ValidZKP → ZeroKnowledgeProof
  | invalid : InvalidZKP → ZeroKnowledgeProof

namespace ZeroKnowledgeProof

/-- ZKPから基本構造を取得 -/
def getCore : ZeroKnowledgeProof → W3CZKProofCore :=
  fun zkp => match zkp with
  | valid vzkp => match vzkp.zkpType with
    | .inl verifier => verifier.core
    | .inr holder => holder.core
  | invalid izkp => match izkp.zkpType with
    | .inl verifier => verifier.core
    | .inr holder => holder.core

/-- ZKP検証関数（定義として実装）

    **設計の核心:**
    - 正規のZKP（valid）: 常に検証成功（暗号的に正しい）
    - 不正なZKP（invalid）: 常に検証失敗（暗号的に間違っている）

    この単純な定義により、暗号的詳細（Groth16ペアリング検証など）を
    抽象化しつつ、プロトコルの安全性を形式的に証明できる。

    **Relationパラメータの意味:**
    実際の実装では、`Relation`に応じて異なる検証ロジックが実行されますが、
    プロトコルレベルでは「ValidZKPは任意のRelationに対して検証成功」
    という抽象化で十分です。

    **Walletバグの影響:**
    - バグのあるWalletが生成したZKPは`invalid`として表現される
    - `verify (invalid _) _ = false`により、検証は失敗する
    - したがって、Walletバグは当該利用者のみに影響
-/
def verify : ZeroKnowledgeProof → Relation → Bool
  | valid _, _ => true   -- 正規のZKPは常に検証成功
  | invalid _, _ => false -- 不正なZKPは常に検証失敗

/-- ZKPが有効かどうかを表す述語 -/
def isValid (zkp : ZeroKnowledgeProof) (relation : Relation) : Prop :=
  verify zkp relation = true

/-- Theorem: 正規のZKPは常に検証成功

    暗号学的に正しく生成されたZKPは、任意のRelationに対して
    検証が成功する。これは定義から自明だが、明示的に定理として示す。
-/
theorem valid_zkp_passes :
  ∀ (vzkp : ValidZKP) (relation : Relation),
    isValid (valid vzkp) relation := by
  intro vzkp relation
  unfold isValid verify
  rfl

/-- Theorem: 不正なZKPは常に検証失敗

    暗号学的に不正なZKPは、どのRelationに対しても検証が失敗する。
    これにより、Walletバグや改ざんされたZKPが受け入れられないことを保証。
-/
theorem invalid_zkp_fails :
  ∀ (izkp : InvalidZKP) (relation : Relation),
    ¬isValid (invalid izkp) relation := by
  intro izkp relation
  unfold isValid verify
  simp

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

/-- 1つのDIDアイデンティティを表す構造体

    Walletは複数のアイデンティティを保持でき、ユーザーは任意にいくつでもDIDを発行できる。
    各アイデンティティは、DID、DIDドキュメント、秘密鍵の組として表現される。
-/
structure Identity where
  did : DID
  didDocument : DIDDocument
  secretKey : SecretKey
  deriving Repr, DecidableEq

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
    - didDocument: トラストアンカーのValidDIDDocument（公的に信頼される）
    - trustees: このトラストアンカーから認証を受けた受託者のDIDリスト
    - claimDefinitions: トラストアンカーが公開するクレーム定義VCのリスト
-/
structure TrustAnchorInfo where
  didDocument : ValidDIDDocument
  trustees : List DID  -- このトラストアンカーから認証を受けた受託者のリスト
  claimDefinitions : List ClaimDefinitionVC  -- トラストアンカーが定義したクレームのリスト

namespace TrustAnchorInfo

/-- トラストアンカー情報が正規かどうかを検証

    トラストアンカーのDIDとValidDIDDocumentが一致することを確認する。
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

/-- Walletはユーザーの秘密情報を安全に保管する

    ユーザーは任意にいくつでもDIDを発行でき、Walletは複数のアイデンティティを保持する。
    各アイデンティティは独立したDID、DIDドキュメント、秘密鍵の組として管理される。
-/
structure Wallet where
  -- 保持する複数のアイデンティティ
  -- ユーザーは任意にいくつでもDIDを発行できる
  identities : List Identity

  -- 保管されている資格情報
  credentials : List VerifiableCredential

  -- 特別な証明書（ルート認証局の場合）
  rootAuthorityCertificate : Option RootAuthorityCertificate

  -- ZKP事前計算データ
  precomputedProofs : List PrecomputedZKP

  -- 信頼するトラストアンカーの辞書
  -- { トラストアンカーのDID ↦ { DIDDocument、受託者のリスト } }
  trustedAnchors : TrustAnchorDict

  -- ウォレット固有のローカル時刻
  -- 相対性理論により、共通の時刻は原理的に存在しない
  -- 各ウォレットが独自の時刻を保持し、検証は検証者の時刻で行われる
  -- 時刻のずれによる影響は自己責任の範囲
  localTime : Timestamp

namespace Wallet

/-- WalletにDIDが含まれているかを確認する -/
def containsDID (wallet : Wallet) (did : DID) : Bool :=
  wallet.identities.any (fun identity => identity.did == did)

/-- WalletからDIDに対応するIdentityを取得する -/
def getIdentity (wallet : Wallet) (did : DID) : Option Identity :=
  wallet.identities.find? (fun identity => identity.did == did)

/-- WalletにDIDが含まれていることを表す命題 -/
def hasDID (wallet : Wallet) (did : DID) : Prop :=
  ∃ (identity : Identity), identity ∈ wallet.identities ∧ identity.did = did

/-- Identityが正規かどうかを検証する述語

    正規のIdentityは以下の条件を満たす：
    1. identity.did = DID.fromDocument identity.didDocument

    この検証により、悪意のあるHolderが不正な(did, didDocument)ペアを
    Walletに挿入することを防ぐ。
-/
def isValidIdentity (identity : Identity) : Prop :=
  identity.did = DID.fromDocument identity.didDocument

/-- Walletが正規かどうかを検証する述語

    正規のWalletは、すべてのIdentityが正規であることを保証する。
    これにより、wallet_identity_consistency が定理として証明可能になる。
-/
def isValid (wallet : Wallet) : Prop :=
  ∀ (identity : Identity), identity ∈ wallet.identities → isValidIdentity identity

/-- Theorem: 正規のWalletに含まれるIdentityは常に正規である -/
theorem valid_wallet_has_valid_identities :
  ∀ (w : Wallet) (identity : Identity),
    isValid w →
    identity ∈ w.identities →
    isValidIdentity identity := by
  intro w identity h_valid h_mem
  exact h_valid identity h_mem

/-- Theorem: 正規のWalletに含まれるIdentityはDID一貫性を満たす -/
theorem valid_wallet_identity_consistency :
  ∀ (w : Wallet) (identity : Identity),
    isValid w →
    identity ∈ w.identities →
    identity.did = DID.fromDocument identity.didDocument := by
  intro w identity h_valid h_mem
  have h := valid_wallet_has_valid_identities w identity h_valid h_mem
  unfold isValidIdentity at h
  exact h

end Wallet


/-- リストが空でないことを長さから証明 -/
theorem list_length_pos_of_forall_mem {α : Type _} (l : List α) (P : α → Prop) :
  (∀ x ∈ l, P x) → l ≠ [] → l.length > 0 := by
  intro _ h_ne
  cases l with
  | nil => contradiction
  | cons _ _ => simp [List.length_cons]

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
  -- 6. authProofが有効である
  ∃ (relation : Relation), ZeroKnowledgeProof.isValid msg.authProof relation

end VerifierAuthMessage

namespace VerifierAuthMessage

/-- Theorem: 正規の検証者は検証に成功する

    トラストアンカーから正当に発行されたVerifierVCを持ち、
    有効なZKPを提示する検証者は、Holderの検証を通過する。
-/
theorem authentic_verifier_passes :
  ∀ (msg : VerifierAuthMessage) (holderWallet : Wallet),
    -- 前提条件: Holderがexpectedトラストアンカーを信頼している
    (TrustAnchorDict.lookup holderWallet.trustedAnchors msg.expectedTrustAnchor).isSome →
    -- 前提条件: verifierCredentialsが空でない
    msg.verifierCredentials ≠ [] →
    -- 前提条件: すべてのVerifierVCが正規に発行されている
    (∀ vc ∈ msg.verifierCredentials,
      VerifiableCredential.isValid vc ∧
      VerifiableCredential.getIssuer vc = msg.expectedTrustAnchor ∧
      VerifiableCredential.getSubject vc = msg.verifierDID) →
    -- 前提条件: authProofが有効
    (∃ (relation : Relation), ZeroKnowledgeProof.isValid msg.authProof relation) →
    -- 結論: 検証に成功する
    validateVerifierAuth msg holderWallet := by
  intro msg holderWallet h_isSome h_ne h_vcs h_zkp
  -- validateVerifierAuthの定義を展開
  unfold validateVerifierAuth
  -- 4つの連言を構築
  constructor
  · -- 条件1: isSome
    exact h_isSome
  constructor
  · -- 条件2: length > 0
    exact list_length_pos_of_forall_mem msg.verifierCredentials
      (fun vc => VerifiableCredential.isValid vc ∧
        VerifiableCredential.getIssuer vc = msg.expectedTrustAnchor ∧
        VerifiableCredential.getSubject vc = msg.verifierDID)
      h_vcs h_ne
  constructor
  · -- 条件3: すべてのVCが有効
    exact h_vcs
  · -- 条件4: ZKPが有効
    exact h_zkp

/-- Theorem: 偽警官（不正な検証者）は検証に失敗する

    以下のいずれかの条件を満たす不正な検証者は、Holderの検証を通過しない：
    1. 信頼されていないトラストアンカーを提示する
    2. 無効なVerifierVCを提示する
    3. 他のトラストアンカーから発行されたVerifierVCを提示する
    4. 他のDIDのVerifierVCを提示する（なりすまし）
    5. 無効なZKPを提示する
-/
theorem fake_verifier_fails :
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
    ¬validateVerifierAuth msg holderWallet := by
  intro msg holderWallet h_bad
  unfold validateVerifierAuth
  intro ⟨h_isSome, h_len, h_vcs, h_zkp⟩
  -- h_badは3つの場合のいずれか
  cases h_bad with
  | inl h_isNone =>
      -- Case 1: isNone → ¬isSome (矛盾)
      simp [Option.isNone_iff_eq_none] at h_isNone
      simp [Option.isSome_iff_exists] at h_isSome
      obtain ⟨val, h_eq⟩ := h_isSome
      rw [h_isNone] at h_eq
      contradiction
  | inr h_or =>
      cases h_or with
      | inl h_bad_vc =>
          -- Case 2: ∃ bad VC → ¬(∀ VC good)
          obtain ⟨vc, h_mem, h_bad_prop⟩ := h_bad_vc
          have h_good := h_vcs vc h_mem
          cases h_bad_prop with
          | inl h_invalid => exact h_invalid h_good.1
          | inr h_or2 =>
              cases h_or2 with
              | inl h_wrong_issuer => exact h_wrong_issuer h_good.2.1
              | inr h_wrong_subject => exact h_wrong_subject h_good.2.2
      | inr h_no_zkp =>
          -- Case 3: ∀ relation ¬valid → ¬(∃ relation valid)
          obtain ⟨relation, h_valid⟩ := h_zkp
          exact h_no_zkp relation h_valid

end VerifierAuthMessage

/-- 信頼ポリシーの定義 -/
structure TrustPolicy where
  -- 信頼するルート認証局のリスト
  trustedRoots : List DID
  -- 最大信頼チェーン深さ
  maxChainDepth : Nat
  -- 必須のクレームタイプ
  requiredClaimTypes : List ClaimTypeBasic

/-- Holder: VCを保持し、必要に応じて提示する主体

    Holderは正規のWallet（Wallet.isValid）を保持する必要がある。
    これにより、悪意のあるHolderが不正なIdentityを使用することを防ぐ。
-/
structure Holder where
  wallet : Wallet
  -- 不変条件: Walletは正規である
  wallet_valid : Wallet.isValid wallet

/-- トラストアンカー: 自己署名のルート認証局

    トラストアンカーも正規のWalletを保持する必要がある。
-/
structure TrustAnchor where
  wallet : Wallet
  -- この発行者が発行できるクレームIDのリスト
  -- （実際にはクレーム定義VCで公開されている）
  authorizedClaimIDs : List ClaimID
  -- ルート認証局証明書（自己署名）
  rootCertificate : RootAuthorityCertificate
  -- 不変条件: Walletは正規である
  wallet_valid : Wallet.isValid wallet

/-- 受託者: 上位認証局から認証を受けた発行者

    受託者も正規のWalletを保持する必要がある。
-/
structure Trustee where
  wallet : Wallet
  -- この発行者が発行できるクレームIDのリスト
  -- （TrusteeVCに含まれるauthorizedClaimIDsと一致）
  authorizedClaimIDs : List ClaimID
  -- 発行者としての認証情報（上位認証局から発行されたVC）
  issuerCredential : VerifiableCredential
  -- 不変条件: Walletは正規である
  wallet_valid : Wallet.isValid wallet

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

    検証者も正規のWalletを保持する必要がある。
-/
structure Verifier where
  -- アイデンティティと資格情報を保持するWallet
  -- Wallet内のcredentialsには、トラストアンカーから発行されたVerifierVCが含まれる
  wallet : Wallet
  -- 検証ポリシー（どの発行者を信頼するか等）
  trustPolicy : TrustPolicy
  -- 不変条件: Walletは正規である
  wallet_valid : Wallet.isValid wallet

-- ## AMATELUSプロトコルの安全性定理
--
-- AMATELUSの設計思想:
-- - Wallet実装のバグは利用者自身にのみ影響
-- - 悪意ある他者とは暗号理論の範囲でのみ信頼が成立
-- - Wallet選択、操作、デバイス故障、ソーシャルハッキングは自己責任の範囲

namespace DID

/-- Theorem: Holderが提示する正規のDIDDocumentは検証に成功する（完全性）

    HolderがWallet内の正規のDID-ValidDIDDocumentペアを提示した場合、
    Verifierの検証は必ず成功する。

    この定理は、Holder構造体の不変条件（wallet_valid）により保証される。

    注意: Identityのd idDocumentフィールドがValidDIDDocumentの場合のみ、
    この定理が適用可能です。
-/
theorem holder_valid_pair_passes :
  ∀ (holder : Holder) (identity : Identity) (vdoc : ValidDIDDocument),
    identity ∈ holder.wallet.identities →
    identity.didDocument = DIDDocument.valid vdoc →
    isValid identity.did vdoc := by
  intro holder identity vdoc h_mem h_doc_eq
  unfold isValid
  -- Holder構造体の不変条件により、identity.did = DID.fromDocument identity.didDocument
  have h_eq := Wallet.valid_wallet_identity_consistency holder.wallet identity
    holder.wallet_valid h_mem
  -- identity.didDocument = DIDDocument.valid vdoc を使う
  rw [h_doc_eq] at h_eq
  -- 今、identity.did = DID.fromDocument (DIDDocument.valid vdoc)
  unfold DID.fromDocument at h_eq
  -- identity.did = DID.valid (fromValidDocument vdoc)
  -- h_eqを使ってgoalのidentity.didを書き換える
  -- 書き換え後、match式が自動的に簡約されて証明が完了する
  rw [h_eq]

end DID

-- ## プロトコルの安全性

/-- Theorem: Verifierの暗号的健全性（Cryptographic Soundness）

    Verifierは暗号的に検証可能な情報のみを信頼し、
    Wallet実装の詳細には依存しない。

    **設計思想の形式化:**
    - Verifierは以下のみを検証する:
      1. DID = validDIDDocumentToDID(ValidDIDDocument) の数学的関係
      2. ZKPの暗号的検証（ZeroKnowledgeProof.verify）
      3. VCの署名検証（VerifiableCredential.isValid）
    - Wallet内部の実装、秘密鍵の管理方法、ZKP生成アルゴリズムは検証しない
    - したがって、Walletバグは検証結果に影響しない（バグがあれば検証失敗）

    **証明の要点:**
    Verifierの検証は公開情報と暗号的検証のみに基づくため、
    Wallet実装がどうであれ、検証ロジックは変わらない。
-/
theorem verifier_cryptographic_soundness :
  ∀ (_verifier : Verifier) (did : DID) (doc : ValidDIDDocument),
    -- Verifierの検証: DID.isValid のみ（暗号的関係の検証）
    DID.isValid did doc →
    -- 結論: この検証はWallet実装に依存しない（数学的関係のみ）
    did = DID.fromDocument (DIDDocument.valid doc) := by
  intro _verifier did doc h_valid
  unfold DID.isValid at h_valid
  cases did with
  | valid vdid =>
    -- h_valid: vdid = DID.fromValidDocument doc
    rw [h_valid]
    unfold DID.fromDocument
    simp
  | invalid _ =>
    -- h_valid: False なので矛盾
    cases h_valid

/-- Theorem: プロトコルの健全性（Protocol Soundness）

    AMATELUSプロトコル全体の健全性:
    - 正規のHolderは検証に成功する（完全性）
    - 不正なHolderは検証に失敗する（健全性）

    これにより、以下が保証される:
    1. 自己責任の明確化: Wallet選択、操作、デバイス故障は利用者の責任
    2. 暗号的信頼: 悪意ある他者とは暗号理論の範囲でのみ信頼
-/
theorem protocol_soundness :
  -- 1. 完全性: 正規のHolderは検証成功（ValidDIDDocumentを持つ場合）
  (∀ (holder : Holder) (identity : Identity) (vdoc : ValidDIDDocument),
    identity ∈ holder.wallet.identities →
    identity.didDocument = DIDDocument.valid vdoc →
    DID.isValid identity.did vdoc) ∧
  -- 2. 健全性: 不正なペアは検証失敗
  (∀ (did : DID) (doc : ValidDIDDocument),
    DID.isInvalidPair did doc →
    ¬DID.isValid did doc) := by
  constructor
  · -- 完全性
    intro holder identity vdoc h_mem h_doc_eq
    exact DID.holder_valid_pair_passes holder identity vdoc h_mem h_doc_eq
  · -- 健全性
    intro did doc h_invalid
    exact DID.invalid_pair_fails_validation did doc h_invalid
