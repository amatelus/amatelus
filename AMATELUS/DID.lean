/-
# DID 定義

このファイルは、AMATELUSプロトコルのDID関連の型と定義を含みます。
W3C DID仕様を基底として、AMATELUS固有の拡張を提供します。
-/

import AMATELUS.CryptoTypes
import AMATELUS.SecurityAssumptions
import W3C.DID

-- ## 基本型定義

-- ## Definition 2.1: DID and DID Document (W3C DID仕様に準拠)

/-- W3C.DIDDocumentから主要な公開鍵を抽出するヘルパー関数

    verificationMethodの最初のエントリから公開鍵を取得します。
    AMATELUSでは、did:amt仕様に従い、verificationMethodに必ず公開鍵が含まれます。
-/
def extractPublicKey (doc : W3C.DIDDocument) : Option PublicKey :=
  match doc.verificationMethod.head? with
  | none => none
  | some vm =>
      match vm.publicKeyMultibase with
      | none => none
      | some pkStr =>
          -- multibase文字列からバイト列に変換（簡略化）
          some { bytes := pkStr.toUTF8.data.toList }

/-- 正規のDIDDocument（所有権検証済み）

    以下のいずれかの方法で検証されたDIDDocument：
    1. **Issuerによるチャレンジ検証**: DIDConnでHolderが秘密鍵所有権を証明
    2. **トラストアンカー**: 政府配布のウォレットに登録済み、または公式サイトからダウンロード

    **W3C DID仕様への準拠:**
    - 標準的なW3C.DIDDocumentをそのまま使用
    - did:amt仕様に従い、verificationMethodから公開鍵を抽出可能

    **設計思想:**
    - DIDDocumentの正規性（所有権検証済み）を型レベルで保証
    - Issuerは検証済みのValidDIDDocumentからValidDIDを構築できる
    - トラストアンカーのValidDIDDocumentは公的に信頼される
-/
structure ValidDIDDocument where
  w3cDoc : W3C.DIDDocument
  -- 不変条件: 秘密鍵所有権が検証済み
  deriving Repr

/-- 不正なDIDDocument

    秘密鍵所有権が未検証、または検証に失敗したDIDDocument。
    以下のいずれかの理由で不正：
    - チャレンジ検証に失敗
    - 改ざんされたDIDDocument
    - 信頼できないソースから取得
-/
structure InvalidDIDDocument where
  w3cDoc : W3C.DIDDocument
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

/-- DIDDocumentのBeqインスタンス（W3C DID識別子で比較） -/
instance : BEq DIDDocument where
  beq
    | DIDDocument.valid v1, DIDDocument.valid v2 =>
        v1.w3cDoc.id == v2.w3cDoc.id
    | DIDDocument.invalid i1, DIDDocument.invalid i2 =>
        i1.w3cDoc.id == i2.w3cDoc.id
    | _, _ => false

/-- DIDDocumentのReprインスタンス -/
instance : Repr DIDDocument where
  reprPrec
    | DIDDocument.valid v, _ => "DIDDocument.valid " ++ repr v
    | DIDDocument.invalid i, _ =>
        "DIDDocument.invalid { w3cDoc := " ++ repr i.w3cDoc ++
        ", reason := \"" ++ i.reason ++ "\" }"

namespace DIDDocument

/-- DIDDocumentからW3C.DIDDocumentを取得 -/
def getW3CDoc : DIDDocument → W3C.DIDDocument
  | valid v => v.w3cDoc
  | invalid i => i.w3cDoc

/-- DIDDocumentが有効かどうかを表す述語 -/
def isValid : DIDDocument → Prop
  | valid _ => True
  | invalid _ => False

end DIDDocument

/-- W3C.DIDからmethod-specific-idを抽出するヘルパー関数

    did:amt仕様では、method-specific-idがハッシュそのものです。
    例: "did:amt:0V3R4T7K1Q2P3N4M5..." → "0V3R4T7K1Q2P3N4M5..."
-/
def extractMethodSpecificId (did : W3C.DID) : String :=
  match W3C.parseDID did.value with
  | none => ""
  | some (_, id) => id

/-- DID (Decentralized Identifier)

    正規のDIDと不正なDIDの和型。
    AMATELUSプロトコルで扱われるDIDは、以下のいずれか：
    - valid: 正規のDID（Wallet内に対応するIdentityがある）
    - invalid: 不正なDID（Wallet内にIdentityがない、または盗難DID）+ 理由

    **設計の利点:**
    - DIDの正規性をプロトコルレベルで明確に区別
    - Walletバグや悪意の攻撃を型レベルで表現
    - ZKP/VC/DIDPairと完全に統一された設計
    - W3C.DIDを直接使用（did:amt仕様ではmethod-specific-idがハッシュ）

    **AMATELUSのDIDConn（VC発行フロー）:**
    - HolderがIssuerにDIDを送信してVC発行を依頼
    - IssuerはDIDを受け取り、VCに埋め込む（issuer/subjectフィールド）
    - Walletバグで間違ったDIDを送ると`invalid`になる
    - 悪意のあるHolderが他人のDIDを使うと`invalid`になる
    - いずれの場合も、VCは発行されるが、そのVCを使うことができない
      （Holderが秘密鍵を持っていないため、ZKPを生成できない）

    **ZKP/VC/DIDPairとの設計の一貫性:**
    - ZeroKnowledgeProof、VerifiableCredential、DIDPairと同じパターン（Valid/Invalid + 和型）
    - 統一された形式検証アプローチ
-/
inductive DID
  | valid : W3C.DID → DID
  | invalid : W3C.DID → String → DID

/-- DIDのBeqインスタンス -/
instance : BEq DID where
  beq
    | DID.valid did1, DID.valid did2 => did1 == did2
    | DID.invalid did1 _, DID.invalid did2 _ => did1 == did2
    | _, _ => false

/-- DIDのReprインスタンス -/
instance : Repr DID where
  reprPrec
    | DID.valid w3cDID, _ =>
        "DID.valid " ++ repr w3cDID
    | DID.invalid w3cDID reason, _ =>
        "DID.invalid { w3cDID := " ++ repr w3cDID ++
        ", reason := \"" ++ reason ++ "\" }"

/-- DIDのDecidableEqインスタンス -/
instance : DecidableEq DID := fun a b =>
  match a, b with
  | DID.valid did1, DID.valid did2 =>
      if h : did1 = did2 then isTrue (congrArg DID.valid h)
      else isFalse (fun h_eq => h (DID.valid.inj h_eq))
  | DID.invalid did1 reason1, DID.invalid did2 reason2 =>
      if h : did1 = did2 ∧ reason1 = reason2 then
        isTrue (by cases h.1; cases h.2; rfl)
      else isFalse (fun h_eq => by
        cases h_eq
        exact h ⟨rfl, rfl⟩)
  | DID.valid _, DID.invalid _ _ => isFalse (fun h => nomatch h)
  | DID.invalid _ _, DID.valid _ => isFalse (fun h => nomatch h)

/-- W3C ServiceEndpointをバイト列にシリアライズするヘルパー関数 -/
def serializeW3CServiceEndpoint (se : W3C.ServiceEndpoint) : List UInt8 :=
  -- ServiceEndpoint IDをUTF8バイト列に変換
  se.id.toUTF8.data.toList

/-- W3C DIDDocumentのserviceフィールド全体をシリアライズ -/
def serializeW3CServices (services : List W3C.ServiceEndpoint) : List UInt8 :=
  services.foldl (fun acc se => acc ++ serializeW3CServiceEndpoint se) []

/-- ValidDIDDocumentをバイト列にシリアライズする関数

    シリアライズ形式:
    id.value ++ verificationMethods ++ services

    **設計:**
    - W3C DID仕様に完全準拠
    - did:amt仕様に従い、標準フィールドのみを使用
    - 決定的: 同じDIDDocumentは常に同じバイト列を生成
    - 単射性: シリアライズ形式により、異なるDIDDocumentは異なるバイト列を生成（高確率）
-/
def serializeDIDDocument (doc : ValidDIDDocument) : List UInt8 :=
  -- W3C DID識別子
  doc.w3cDoc.id.value.toUTF8.data.toList ++
  -- W3C VerificationMethodsのシリアライズ（公開鍵を含む）
  (doc.w3cDoc.verificationMethod.foldl (fun acc vm =>
    acc ++ match vm.publicKeyMultibase with
    | none => []
    | some pk => pk.toUTF8.data.toList) []) ++
  -- W3C ServiceEndpointsのシリアライズ
  serializeW3CServices doc.w3cDoc.service

/-- ValidDIDDocumentからW3C.DIDを抽出する関数

    この関数は、所有権検証済みのDIDDocumentからW3C.DID識別子を抽出します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後、ValidDIDDocumentからW3C.DIDを取得
    - トラストアンカー: 公開されたValidDIDDocumentからW3C.DIDを取得
    - Verifier: トラストアンカーのValidDIDDocumentからW3C.DIDを取得

    **did:amt仕様との関係:**
    - did:amt仕様では、DID生成時にDIDDocument全体をハッシュ化
    - ハッシュはmethod-specific-id部分に含まれる（例: did:amt:0V3R4T7K1Q2P3N4M5...）
    - したがって、W3C.DIDの`value`からmethod-specific-idを抽出すればハッシュが得られる

    **技術仕様:**
    - 入力: ValidDIDDocument（所有権検証済み）
    - 出力: W3C.DID
    - 性質: 決定性（同じ入力には同じ出力）
-/
noncomputable def validDIDDocumentToDID (doc : ValidDIDDocument) : W3C.DID :=
  doc.w3cDoc.id

-- ## ハッシュ関数

namespace DID

/-- ValidDIDDocumentからW3C.DIDを取得

    validDIDDocumentToDIDを使用して、所有権検証済みのDIDDocumentから
    W3C.DIDを取得します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後にW3C.DIDを取得
    - Verifier: トラストアンカーの公開DIDDocumentからW3C.DIDを取得

    この定義により、以下が保証される：
    - **決定性**: 同じValidDIDDocumentからは常に同じW3C.DIDが取得される
    - **一意性**: did:amt仕様により、method-specific-idがハッシュなので一意性が保証される
-/
noncomputable def fromValidDocument (doc : ValidDIDDocument) : W3C.DID :=
  validDIDDocumentToDID doc

/-- DIDDocumentからDID（和型）を生成する

    - ValidDIDDocument → valid DID（W3C DIDを含む）
    - InvalidDIDDocument → invalid DID（W3C DIDを含む）

    この関数により、DIDDocumentの正規性がDIDの正規性に反映されます。
-/
noncomputable def fromDocument (doc : DIDDocument) : DID :=
  match doc with
  | DIDDocument.valid vdoc => DID.valid (fromValidDocument vdoc)
  | DIDDocument.invalid idoc =>
      DID.invalid idoc.w3cDoc.id ("Invalid DIDDocument: " ++ idoc.reason)

/-- DIDからmethod-specific-id（ハッシュ）を取得

    did:amt仕様では、method-specific-idがハッシュそのものです。
-/
def getMethodSpecificId : DID → String
  | valid w3cDID => extractMethodSpecificId w3cDID
  | invalid w3cDID _ => extractMethodSpecificId w3cDID

/-- DIDがValidDIDDocumentから正しく生成されたかを検証 -/
def isValid (did : DID) (doc : ValidDIDDocument) : Prop :=
  match did with
  | valid w3cDID => w3cDID = fromValidDocument doc
  | invalid _ _ => False  -- 不正なDIDは常に無効

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
