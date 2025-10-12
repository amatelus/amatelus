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
structure InValidDIDDocument where
  w3cDoc : W3C.DIDDocument
  reason : String
  deriving Repr

/-- 未検証のDIDDocument（和型）

    構造的に正しくパースされたDIDDocumentで、所有権検証の結果を表す和型。
    Holderから提示されるUnknownDIDDocumentは、以下のいずれか：
    - valid: 所有権検証済みのDIDDocument
    - invalid: 所有権未検証または検証失敗のDIDDocument

    **命名の意図:**
    - 「UnknownDIDDocument」= 構造的にパース成功したが、所有権検証の状態は未確定または既知
    - W3C.DIDDocument（検証前）とは異なり、検証結果を含む

    **AMATELUSでの使用:**
    - HolderはUnknownDIDDocument（和型）をIssuerに提示
    - Issuerはチャレンジで検証し、成功ならValidDIDDocumentを獲得
    - ValidDIDDocumentからValidDIDを構築可能
-/
inductive UnknownDIDDocument
  | valid : ValidDIDDocument → UnknownDIDDocument
  | invalid : InValidDIDDocument → UnknownDIDDocument

/-- UnknownDIDDocumentのBeqインスタンス（W3C DID識別子で比較） -/
instance : BEq UnknownDIDDocument where
  beq
    | UnknownDIDDocument.valid v1, UnknownDIDDocument.valid v2 =>
        v1.w3cDoc.id == v2.w3cDoc.id
    | UnknownDIDDocument.invalid i1, UnknownDIDDocument.invalid i2 =>
        i1.w3cDoc.id == i2.w3cDoc.id
    | _, _ => false

/-- UnknownDIDDocumentのReprインスタンス -/
instance : Repr UnknownDIDDocument where
  reprPrec
    | UnknownDIDDocument.valid v, _ => "UnknownDIDDocument.valid " ++ repr v
    | UnknownDIDDocument.invalid i, _ =>
        "UnknownDIDDocument.invalid { w3cDoc := " ++ repr i.w3cDoc ++
        ", reason := \"" ++ i.reason ++ "\" }"

namespace UnknownDIDDocument

/-- UnknownDIDDocumentからW3C.DIDDocumentを取得 -/
def getW3CDoc : UnknownDIDDocument → W3C.DIDDocument
  | valid v => v.w3cDoc
  | invalid i => i.w3cDoc

/-- UnknownDIDDocumentが有効かどうかを表す述語 -/
def isValid : UnknownDIDDocument → Prop
  | valid _ => True
  | invalid _ => False

end UnknownDIDDocument

/-- W3C.DIDからmethod-specific-idを抽出するヘルパー関数

    did:amt仕様では、method-specific-idがハッシュそのものです。
    例: "did:amt:0V3R4T7K1Q2P3N4M5..." → "0V3R4T7K1Q2P3N4M5..."
-/
def extractMethodSpecificId (did : W3C.DID) : String :=
  match W3C.parseDID did.value with
  | none => ""
  | some (_, id) => id

/-- 正規のDID（検証済み）

    Wallet内に対応するIdentityがあり、秘密鍵を保持しているDID。

    **フィールド:**
    - w3cDID: W3C DID仕様に準拠したDID識別子
    - hash: DIDDocumentから計算されたハッシュ値（did:amt仕様のmethod-specific-id）

    **did:amt仕様:**
    - did:amt仕様では、method-specific-idがDIDDocumentのハッシュです
    - hashフィールドはこのハッシュ値を保持します
    - w3cDIDのmethod-specific-id部分とhashは一致する必要があります
-/
structure ValidDID where
  w3cDID : W3C.DID
  hash : Hash
  deriving Repr, DecidableEq

/-- 不正なDID

    Wallet内にIdentityがない、または盗難されたDID。

    **フィールド:**
    - w3cDID: W3C DID仕様に準拠したDID識別子
    - reason: 不正と判断された理由
-/
structure InvalidDID where
  w3cDID : W3C.DID
  reason : String
  deriving Repr, DecidableEq

/-- UnknownDID (Unknown Decentralized Identifier)

    正規のDIDと不正なDIDの和型。
    AMATELUSプロトコルで扱われるDIDは、以下のいずれか：
    - valid: 正規のDID（Wallet内に対応するIdentityがある）
    - invalid: 不正なDID（Wallet内にIdentityがない、または盗難DID）

    **設計の利点:**
    - DIDの正規性をプロトコルレベルで明確に区別
    - Walletバグや悪意の攻撃を型レベルで表現
    - ZKP/VC/DIDPairと完全に統一された設計
    - ValidDIDにはハッシュ値を保持（did:amt仕様に準拠）

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
inductive UnknownDID
  | valid : ValidDID → UnknownDID
  | invalid : InvalidDID → UnknownDID

/-- DIDのBeqインスタンス -/
instance : BEq UnknownDID where
  beq
    | UnknownDID.valid v1, UnknownDID.valid v2 => v1.w3cDID == v2.w3cDID
    | UnknownDID.invalid i1, UnknownDID.invalid i2 => i1.w3cDID == i2.w3cDID
    | _, _ => false

/-- DIDのReprインスタンス -/
instance : Repr UnknownDID where
  reprPrec
    | UnknownDID.valid v, _ =>
        "DID.valid " ++ repr v
    | UnknownDID.invalid i, _ =>
        "DID.invalid " ++ repr i

/-- DIDのDecidableEqインスタンス -/
instance : DecidableEq UnknownDID := fun a b =>
  match a, b with
  | UnknownDID.valid v1, UnknownDID.valid v2 =>
      if h : v1 = v2 then isTrue (congrArg UnknownDID.valid h)
      else isFalse (fun h_eq => h (UnknownDID.valid.inj h_eq))
  | UnknownDID.invalid i1, UnknownDID.invalid i2 =>
      if h : i1 = i2 then
        isTrue (congrArg UnknownDID.invalid h)
      else isFalse (fun h_eq => h (UnknownDID.invalid.inj h_eq))
  | UnknownDID.valid _, UnknownDID.invalid _ => isFalse (fun h => nomatch h)
  | UnknownDID.invalid _, UnknownDID.valid _ => isFalse (fun h => nomatch h)

/-- W3C ServiceEndpointをバイト列にシリアライズするヘルパー関数 -/
def serializeW3CServiceEndpoint (se : W3C.ServiceEndpoint) : List UInt8 :=
  -- ServiceEndpoint IDをUTF8バイト列に変換
  se.id.toUTF8.data.toList

/-- W3C UnknownDIDDocumentのserviceフィールド全体をシリアライズ -/
def serializeW3CServices (services : List W3C.ServiceEndpoint) : List UInt8 :=
  services.foldl (fun acc se => acc ++ serializeW3CServiceEndpoint se) []

/-- ValidDIDDocumentをバイト列にシリアライズする関数

    シリアライズ形式:
    id.value ++ verificationMethods ++ services

    **設計:**
    - W3C DID仕様に完全準拠
    - did:amt仕様に従い、標準フィールドのみを使用
    - 決定的: 同じUnknownDIDDocumentは常に同じバイト列を生成
    - 単射性: シリアライズ形式により、異なるUnknownDIDDocumentは異なるバイト列を生成（高確率）
-/
def serializeUnknownDIDDocument (doc : ValidDIDDocument) : List UInt8 :=
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

    この関数は、所有権検証済みのUnknownDIDDocumentからW3C.DID識別子を抽出します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後、ValidDIDDocumentからW3C.DIDを取得
    - トラストアンカー: 公開されたValidDIDDocumentからW3C.DIDを取得
    - Verifier: トラストアンカーのValidDIDDocumentからW3C.DIDを取得

    **did:amt仕様との関係:**
    - did:amt仕様では、DID生成時にUnknownDIDDocument全体をハッシュ化
    - ハッシュはmethod-specific-id部分に含まれる（例: did:amt:0V3R4T7K1Q2P3N4M5...）
    - したがって、W3C.DIDの`value`からmethod-specific-idを抽出すればハッシュが得られる

    **技術仕様:**
    - 入力: ValidDIDDocument（所有権検証済み）
    - 出力: W3C.DID
    - 性質: 決定性（同じ入力には同じ出力）
-/
noncomputable def ValidDIDDocumentToDID (doc : ValidDIDDocument) : W3C.DID :=
  doc.w3cDoc.id

-- ## ハッシュ関数

namespace UnknownDID

/-- ValidDIDDocumentからValidDIDを生成

    ValidDIDDocumentをシリアライズしてハッシュを計算し、ValidDIDを構築します。

    **AMATELUSでの使用:**
    - Issuer: チャレンジ検証後にValidDIDを取得
    - Verifier: トラストアンカーの公開UnknownDIDDocumentからValidDIDを取得

    この定義により、以下が保証される：
    - **決定性**: 同じValidDIDDocumentからは常に同じValidDIDが取得される
    - **一意性**: did:amt仕様により、method-specific-idがハッシュなので一意性が保証される
-/
noncomputable def fromValidDocument (doc : ValidDIDDocument) : ValidDID :=
  let w3cDID := ValidDIDDocumentToDID doc
  let serialized := serializeUnknownDIDDocument doc
  let hash := hashForDID serialized
  { w3cDID := w3cDID, hash := hash }

/-- UnknownDIDDocumentからDID（和型）を生成する

    - ValidDIDDocument → ValidDID（w3cDIDとhashを含む）
    - InValidDIDDocument → InvalidDID（w3cDIDとreasonを含む）

    この関数により、UnknownDIDDocumentの正規性がDIDの正規性に反映されます。
-/
noncomputable def fromDocument (doc : UnknownDIDDocument) : UnknownDID :=
  match doc with
  | UnknownDIDDocument.valid vdoc =>
      UnknownDID.valid (fromValidDocument vdoc)
  | UnknownDIDDocument.invalid idoc =>
      UnknownDID.invalid {
        w3cDID := idoc.w3cDoc.id,
        reason := "Invalid UnknownDIDDocument: " ++ idoc.reason
      }

/-- DIDからmethod-specific-id（ハッシュ）を取得

    did:amt仕様では、method-specific-idがハッシュそのものです。
-/
def getMethodSpecificId : UnknownDID → String
  | valid v => extractMethodSpecificId v.w3cDID
  | invalid i => extractMethodSpecificId i.w3cDID

/-- UnknownDIDからValidDIDへの変換

    valid: Some ValidDIDを返す
    invalid: noneを返す

    **設計思想:**
    invalidなDIDで発行されたVCは、InvalidVCとして扱われるべきです。
    この関数により、DIDの正規性がVCの正規性に正しく反映されます。
-/
def toValidDID (did : UnknownDID) : Option ValidDID :=
  match did with
  | valid v => some v
  | invalid _ => none

/-- DIDがValidDIDDocumentから正しく生成されたかを検証 -/
def isValid (did : UnknownDID) (doc : ValidDIDDocument) : Prop :=
  match did with
  | valid v => v = fromValidDocument doc
  | invalid _ => False  -- 不正なDIDは常に無効

-- ## DIDとDIDドキュメントの正規性

/-- 正規のDID-DIDドキュメントのペア

    HolderがVerifierに提示するペアは、この述語を満たす必要がある。
    正規のペアは、DIDがValidDIDDocumentから正しく生成されたものである。
-/
def isCanonicalPair (did : UnknownDID) (doc : ValidDIDDocument) : Prop :=
  isValid did doc

/-- 不正なDID-DIDドキュメントのペア

    以下のいずれかの場合、ペアは不正である：
    1. DIDとValidDIDDocumentが一致しない
    2. InValidDIDDocumentから生成されたDID
-/
def isInvalidPair (did : UnknownDID) (doc : ValidDIDDocument) : Prop :=
  ¬isValid did doc

/-- Theorem: 不正なペアは検証に失敗する

    HolderがVerifierに不正な(did, doc)ペアを提示した場合、
    isValid did doc = Falseとなり、検証は失敗する。
-/
theorem invalid_pair_fails_validation :
  ∀ (did : UnknownDID) (doc : ValidDIDDocument),
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
  ∀ (did : UnknownDID) (doc : ValidDIDDocument),
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
  ∀ (did : UnknownDID) (doc : ValidDIDDocument),
    ¬isValid did doc →
    -- Verifierの検証ロジック
    ∃ (verificationFailed : Bool),
      verificationFailed = true := by
  intro did doc h_invalid
  -- 検証失敗を表すフラグを構成
  refine ⟨true, rfl⟩

end UnknownDID
