/-
# Zero-Knowledge Proof 定義

このファイルは、AMATELUSプロトコルのゼロ知識証明（ZKP）関連の型と定義を含みます。
-/

import AMATELUS.DID

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

/-- Zero-Knowledge Proof の基本構造

    すべてのZKPはこの基本構造を含む。

    **注意:** W3Cが標準化しているのは一般的な`proof`構造であり、
    ZKP固有の構造ではありません。この構造はAMATELUSのZKP実装のために定義されています。

    参考: W3C VC Data Model 2.0 の Proof 仕様（一般的な証明構造）
-/
structure ZKProofCore where
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
  core : ZKProofCore
  verifierDID : UnknownDID           -- 証明者（Verifier）のDID
  challengeNonce : Nonce      -- 双方向チャレンジnonce: H(nonce_holder || nonce_verifier)
  credentialType : String     -- 証明対象のVC種類（"VerifierVC"など）

/-- Holder資格証明用ZKPの基本構造

    Holderが特定の属性を証明するためのZKP。
    "私は特定の属性を満たすVCを保持している"ことを証明。
    例: "私は20歳以上である"、"私は運転免許を持っている"など

    **ゼロ知識性の保証:**
    HolderのDIDは含まれない。ZKPの本質は「誰が」ではなく「何を」証明するか。
    Verifierは属性の正当性のみを検証し、Holderの身元は知らない。

    **双方向ナンス:**
    両方のナンスを明示的に格納することで、リプレイ攻撃耐性を実現。
    - holderNonce: Holderが生成したnonce（相互認証時）
    - verifierNonce: Verifierが生成したnonce
    - どちらか一方が一意なら、ペア全体が一意（相互防衛）

    この設計により、どちらか一方のWalletにバグがあっても、
    もう一方のランダムネスにより保護される。
    「他人のWalletバグから被害を受けない」設計原則を保証。
-/
structure HolderCredentialZKPCore where
  core : ZKProofCore
  holderNonce : Nonce         -- Holderが生成したnonce
  verifierNonce : Nonce       -- Verifierが生成したnonce
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

/-- 未検証のゼロ知識証明 (Unknown Zero-Knowledge Proof)

    正規のZKPと不正なZKPの和型。
    AMATELUSプロトコルで扱われるZKPは、暗号学的に以下のいずれか：
    - valid: 正規に生成されたZKP（暗号的に正しい）
    - invalid: 不正なZKP（暗号的に間違っている、または改ざんされている）

    **設計の利点:**
    - ZKP検証の暗号的詳細（Groth16のペアリング計算など）を抽象化
    - プロトコルレベルでは「正規/不正」の区別のみが重要
    - Wallet実装のバグは`invalid`として表現され、プロトコルの安全性には影響しない
-/
inductive UnknownZKP
  | valid : ValidZKP → UnknownZKP
  | invalid : InvalidZKP → UnknownZKP

namespace UnknownZKP

/-- ZKPから基本構造を取得 -/
def getCore : UnknownZKP → ZKProofCore :=
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
def verify : UnknownZKP → Relation → Bool
  | valid _, _ => true   -- 正規のZKPは常に検証成功
  | invalid _, _ => false -- 不正なZKPは常に検証失敗

/-- ZKPが有効かどうかを表す述語 -/
def isValid (zkp : UnknownZKP) (relation : Relation) : Prop :=
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

end UnknownZKP

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
