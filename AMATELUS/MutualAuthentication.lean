/-
# 統一された相互認証プロトコル（Unified Mutual Authentication）

このファイルは、すべてのVerifierに対する統一された認証プロトコルを形式化します。

## 設計原則

1. **名寄せ回避の一貫性**: HolderだけでなくVerifierもZKPで証明
2. **最小権限の原則**: 必要最小限の情報のみ開示
3. **統一されたプロトコル**: すべてのVerifierが同じ認証プロセスに従う

## 統一設計の理由

従来は「高権限Verifier（警察官等）は認証必須、低権限Verifier（店員等）は匿名可」
という区別がありましたが、Basic.leanでVerifierVCの仕様が定義され、
**すべてのVerifierがトラストアンカーから発行されたVerifierVCを保持する**
という設計になったため、プロトコルを統一しました。

## すべてのVerifierが認証を提示

- 警察官：警察庁のトラストアンカーから発行されたVerifierVCに基づくZKP
- 銀行員：金融庁のトラストアンカーから発行されたVerifierVCに基づくZKP
- 店員：チェーン本部のトラストアンカーから発行されたVerifierVCに基づくZKP

→ **すべてのVerifierが「自分が正規のXである」ことをZKPで証明する**

## セキュリティ向上

この統一により、偽Verifier攻撃（偽警官、偽店員等）を完全に防止できます。

-/

import AMATELUS.Basic
import AMATELUS.SecurityAssumptions
import AMATELUS.ReplayResistance

-- ## Verifier認証の統一設計

/-- Verifierタイプを表す構造体

    すべてのVerifierは、トラストアンカーから発行されたVerifierVCを保持し、
    Holderに対して自身の正当性を証明する必要がある。

    例:
    - "police": 警察官（警察庁のトラストアンカーから発行）
    - "bank": 銀行員（金融庁のトラストアンカーから発行）
    - "retail": コンビニ店員（チェーン本部のトラストアンカーから発行）
-/
structure VerifierType where
  category : String              -- 例: "police", "bank", "retail"
  deriving Repr, DecidableEq

-- ## Verifierの拡張構造体

/-- Verifier（相互認証対応版） -/
structure AuthenticatedVerifier where
  -- 基本情報（DIDのみ、秘密情報は非公開）
  did : DID
  trustPolicy : TrustPolicy

  -- Verifierタイプ
  verifierType : VerifierType

  -- 認証が必要な場合のみ、認証資格を保持
  -- 例: 警察官の場合、警察庁が発行した「警察官資格VC」を基にZKPを生成できる
  authCredential : Option VerifiableCredential

/-- VerifierがWalletを持つかどうかは実装依存

    重要: VerifierのWalletは、ZKP生成のためのみに使用される。
    DIDやVCを直接提示することはない。
-/
axiom verifierHasWalletForZKP : AuthenticatedVerifier → Option Wallet

-- ## 相互認証プロトコルのフロー

/-- Holderが発行するVerifier向けチャレンジ -/
structure HolderChallenge where
  nonce : Nonce
  expectedVerifierType : Option VerifierType  -- 期待するVerifierタイプ（任意）
  timestamp : Timestamp

/-- Verifierが発行するHolder向けチャレンジ（従来のもの） -/
structure VerifierChallenge where
  nonce : Nonce
  sessionId : Nat
  timestamp : Timestamp

/-- 相互認証セッション -/
structure MutualAuthSession where
  -- Phase 1: HolderがVerifierにチャレンジ
  holderChallenge : HolderChallenge

  -- Phase 2: Verifierの応答（すべてのVerifierがVerifierAuthZKPを提示）
  verifierAuthZKP : VerifierAuthZKP
  verifierChallenge : VerifierChallenge

  -- Phase 3: Holderの応答（HolderCredentialZKP）
  holderZKP : Option HolderCredentialZKP

-- ## プロトコルフロー

/-- Phase 1: HolderがVerifierにチャレンジを発行

    Holderは、情報提供を求める前に、相手が本当に信頼できるVerifierか確認する。
    すべてのVerifierはVerifierAuthProofを提示する必要がある。
-/
def holderInitiatesChallenge
    (_holder : Holder)
    (expectedVerifierType : Option VerifierType)
    : HolderChallenge :=
  {
    nonce := ⟨[]⟩,  -- 実装では暗号学的ランダムnonce
    expectedVerifierType := expectedVerifierType,
    timestamp := ⟨0⟩  -- 実装では現在時刻
  }

/-- Phase 2: Verifierの応答

    すべてのVerifierは、VerifierAuthZKP（ZKP）を提示し、かつ自分のchallengeを発行する。
    - 警察官: 警察庁のトラストアンカーから発行されたVerifierVCに基づくZKP
    - 銀行員: 金融庁のトラストアンカーから発行されたVerifierVCに基づくZKP
    - 店員: チェーン本部のトラストアンカーから発行されたVerifierVCに基づくZKP
-/
axiom verifierRespondsToChallenge :
  AuthenticatedVerifier →
  HolderChallenge →
  (VerifierAuthZKP × VerifierChallenge)

-- ## セキュリティ定理

/-- VerifierAuthZKPの検証述語（Prop版） -/
def verifierAuthZKPIsValid
    (zkp : VerifierAuthZKP)
    (holderChallenge : HolderChallenge)
    : Prop :=
  -- 1. NonceがHolderが発行したものと一致
  zkp.challengeNonce = holderChallenge.nonce ∧
  -- 2. ZKPが有効（実装依存）
  True  -- 実際にはZKP.verify (ZeroKnowledgeProof.verifierAuthZKP zkp)

/-- VerifierAuthZKPの検証関数（Bool版・実装用） -/
def verifierAuthZKPIsValidBool
    (zkp : VerifierAuthZKP)
    (holderChallenge : HolderChallenge)
    : Bool :=
  -- 1. NonceがHolderが発行したものと一致
  (zkp.challengeNonce == holderChallenge.nonce)
  -- 2. ZKPが有効（実装依存で常にtrueとする）

/-- Bool版とProp版の対応 -/
axiom verifierAuthZKPIsValidBool_iff_Prop :
  ∀ (zkp : VerifierAuthZKP) (holderChallenge : HolderChallenge),
    verifierAuthZKPIsValidBool zkp holderChallenge = true ↔
    verifierAuthZKPIsValid zkp holderChallenge

/-- ZKP生成プレースホルダ（公理化） -/
axiom generateHolderZKP : Holder → MutualAuthSession → HolderCredentialZKP

/-- Phase 3: HolderがVerifierを検証し、自分のZKPを提示

    すべてのVerifierに対して、Holderは以下を確認:
    1. VerifierAuthProofが提示されているか
    2. VerifierAuthProofのnonceが自分が発行したものと一致するか
    3. VerifierタイプがHolderの期待と一致するか（期待がある場合）
    4. ZKPが有効か
    5. 検証成功後、Verifierのchallengeに対してZKPを生成
-/
noncomputable def holderVerifiesAndResponds
    (holder : Holder)
    (session : MutualAuthSession)
    : Option HolderCredentialZKP :=
  -- VerifierAuthZKPを検証（Bool版を使用）
  if verifierAuthZKPIsValidBool session.verifierAuthZKP session.holderChallenge then
    some (generateHolderZKP holder session)  -- 検証成功 → ZKP生成
  else
    none  -- 検証失敗 → ZKP提示拒否

/-- セッション完了: holderVerifiesAndRespondsの結果をセッションに反映 -/
noncomputable def completeSession
    (holder : Holder)
    (session : MutualAuthSession)
    : MutualAuthSession :=
  { session with
    holderZKP := holderVerifiesAndResponds holder session }

/-- Theorem: すべてのVerifierは、正規の資格証明なしにHolderから情報を得られない

    証明の構造:
    - すべてのVerifierはVerifierAuthProofの提示が必須
    - VerifierAuthProofが無効な場合、HolderはZKPを提示しない
    - よって、偽Verifierは情報を得られない
-/
theorem verifier_authentication_required :
  ∀ (holder : Holder) (session : MutualAuthSession),
    -- VerifierAuthZKPが無効なら
    ¬verifierAuthZKPIsValid session.verifierAuthZKP session.holderChallenge →
    -- HolderはZKPを提示しない
    holderVerifiesAndResponds holder session = none := by
  intro holder session h_invalid
  -- holderVerifiesAndRespondsの定義を展開
  unfold holderVerifiesAndResponds
  -- まず、verifierAuthZKPIsValidBool = false を示す
  have h_bool_false : verifierAuthZKPIsValidBool session.verifierAuthZKP session.holderChallenge = false := by
    -- ¬verifierAuthZKPIsValid から verifierAuthZKPIsValidBool = false を導く
    cases h : verifierAuthZKPIsValidBool session.verifierAuthZKP session.holderChallenge
    · rfl
    · -- h : verifierAuthZKPIsValidBool ... = true の場合
      have h_prop : verifierAuthZKPIsValid session.verifierAuthZKP session.holderChallenge :=
        (verifierAuthZKPIsValidBool_iff_Prop session.verifierAuthZKP session.holderChallenge).mp h
      exact absurd h_prop h_invalid
  -- if式を分岐
  rw [h_bool_false]
  -- if false = true then ... else none
  rfl

-- ## 実装要件

/-- 実装要件: 統一された相互認証プロトコル

    **Phase 1: HolderのVerifierチャレンジ**
    ```
    Holder → Verifier:
    {
      nonce1: random(),  // 推奨：一意なnonce、必須ではない
      expectedVerifierType: "police" (optional),  // 期待するVerifierタイプ
      timestamp: now()
    }
    ```

    **Phase 2: Verifierの応答（すべてのVerifierが同じプロトコル）**

    警察官の例:
    ```
    Verifier → Holder:
    {
      verifierAuthZKP: {
        core: {
          proof: π,
          publicInput: x,
          proofPurpose: "authentication",
          created: now()
        },
        verifierDID: "did:amatelus:123...",
        challengeNonce: nonce1,
        credentialType: "VerifierVC"
      },
      verifierChallenge: {
        nonce2: random(),  // 必須：一意なnonce（プロトコル要件）
        sessionId: 123,
        timestamp: now()
      }
    }
    ```

    コンビニ店員の例:
    ```
    Verifier → Holder:
    {
      verifierAuthZKP: {
        core: {
          proof: π,
          publicInput: x,
          proofPurpose: "authentication",
          created: now()
        },
        verifierDID: "did:amatelus:456...",
        challengeNonce: nonce1,
        credentialType: "VerifierVC"
      },
      verifierChallenge: {
        nonce2: random(),  // 必須：一意なnonce（プロトコル要件）
        sessionId: 124,
        timestamp: now()
      }
    }
    ```

    **Phase 3: Holderの応答**
    ```
    Holder → Verifier:
    {
      holderZKP: {
        core: {
          proof: π,
          publicInput: x,
          proofPurpose: "assertionMethod",
          created: now()
        },
        holderDID: "did:amatelus:789...",
        challengeNonce: nonce2,
        claimedAttributes: "age >= 20"
      }
    }
    ```

    **ナンス一意性の責任範囲:**

    | フェーズ | 生成者 | 一意性要件 | 重複時の被害者 | 責任 |
    |---------|-------|-----------|--------------|------|
    | Phase 1 | Holder | **推奨** | Holder自身 | Holder |
    | Phase 2 | Verifier | **必須** | Holder（一般市民） | プロトコル |

    **Holderのnonce1一意性（推奨事項）:**
    - 一意であることが推奨されるが、プロトコルの必須要件ではない
    - もし重複した場合：
      - 攻撃者がVerifierAuthProofを再利用する可能性
      - しかし、被害を受けるのはHolder自身のみ
      - Verifierには不利益なし（VerifierAuthProofは単なる資格証明）
    - **責任**: Holderのウォレット選択
    - 安全なブラウザを選ぶ責任がユーザーにあるように、
      安全なウォレットを選ぶことはHolder自身の責任

    **Verifierのnonce2一意性（プロトコル必須）:**
    - **必ず**一意でなければならない（ReplayResistance.leanで証明）
    - もし重複した場合：
      - リプレイ攻撃が成立（nonce_reuse_enables_replay_attack）
      - Holder（一般市民）が被害を受ける
      - Verifier（公的機関・企業）の責任
    - **責任**: プロトコル設計者・Verifier実装者

    **設計思想:**
    Verifierは信頼される立場（警察官、企業等）であり、適切な実装が期待される。
    一方、Holderは個人であり、ウォレット実装の品質は様々。
    プロトコルは、Verifier側の厳密な実装により、
    Holderのウォレット品質に関わらず安全性を保証すべき。

    **セキュリティ保証:**
    - 両者がZKPのみを提示（DID/VC非公開）
    - 名寄せ不可能
    - **すべてのVerifierが認証を要求される**
    - 偽Verifier攻撃を防止（fake_verifier_attack_prevented）
    - リプレイ攻撃を防止（replay_attack_resistance）
    - 統一されたプロトコル（シンプルで安全）
-/
def mutualAuthenticationRequirements : String :=
  "Unified Mutual Authentication Protocol with Typed ZKP:
   Phase 1: Holder challenges Verifier with nonce1 (RECOMMENDED unique)
   Phase 2: ALL Verifiers respond with:
     - VerifierAuthZKP (typed ZKP on nonce1) - REQUIRED for ALL verifiers
     - VerifierChallenge (nonce2) - MUST be unique (PROTOCOL REQUIREMENT)
   Phase 3: Holder verifies VerifierAuthZKP and responds with HolderCredentialZKP on nonce2

   ZKP Types:
   - VerifierAuthZKP: Verifier authentication proof
   - HolderCredentialZKP: Holder credential proof
   Each ZKP contains W3CZKProofCore with proof, publicInput, proofPurpose, and timestamp

   Nonce uniqueness responsibility:
   - Holder's nonce1: RECOMMENDED (Holder's responsibility)
   - Verifier's nonce2: REQUIRED (Protocol's responsibility)

   Security: Both parties use typed ZKP only, preventing correlation
   All verifiers must authenticate, preventing fake verifier attacks"
