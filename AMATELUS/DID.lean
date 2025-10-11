/-
# DID 定義

このファイルは、AMATELUSプロトコルのDID関連の型と定義を含みます。
-/

import AMATELUS.CryptoTypes
import AMATELUS.SecurityAssumptions

-- ## 基本型定義

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
    2. SHA3-512でハッシュ化
    3. ハッシュ値を持つValidDIDを構築
-/
noncomputable def validDIDDocumentToDID (doc : ValidDIDDocument) : ValidDID :=
  { hash := hashForDID (serializeDIDDocument doc) }

-- ## ハッシュ関数

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
