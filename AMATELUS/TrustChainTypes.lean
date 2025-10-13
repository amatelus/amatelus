/-
# トラストチェーン型定義（N階層対応）

このファイルは、AMATELUSプロトコルのN階層委任に対応した
トラストチェーン関連の基本型定義を含みます。

**設計原則:**
1. プロトコルレベルの上限なし（各委任者がmaxDepthを設定）
2. 単調減少性（nextDepth = min(parentDepth - 1, delegation.maxDepth)）
3. 循環委任の防止（DID重複チェック）
4. Nat型の性質により有限回の委任で必ずゼロに到達
5. Lean4で形式的に停止性を証明
-/

import AMATELUS.DID
import AMATELUS.JSONSchema

/-- 初期最大信頼チェーン深さ（N階層対応）

    新設計では、プロトコルレベルの上限を設けない。
    各委任者がmaxDepthを指定し、単調減少により有限回で停止することを保証する。

    この値は検証アルゴリズムの初期remainingDepthとして使用される。
    実際の制限は各delegationのmaxDepthで決まる。
-/
def InitialMaxDepth : Nat := 1000

-- ## Section 5.1: DelegationContent型

/-- 委任内容（Delegation Content）- maxDepth対応

    委任者から受託者へのクレーム発行権限の委譲を表現する構造。

    **設計思想:**
    - grantorDID: 権限を与える側のDID
    - granteeDID: 権限を受ける側のDID
    - label: クレームの表示ラベル（人間向け、機能を持たない）
    - claimSchema: JSON Schema（正式な定義）
    - maxDepth: 最大委任階層数（1以上の自然数、必須）

    **maxDepthの役割:**
    - この委任からさらに何階層まで委任を許可するか
    - 受託者は親のremainingDepth-1と自分のmaxDepthの小さい方まで委任可能
    - 計算式：nextDepth = min(parentDepth - 1, delegation.maxDepth)
-/
structure DelegationContent where
  /-- 委任者DID（権限を与える側） -/
  grantorDID : ValidDID
  /-- 受託者DID（権限を受ける側） -/
  granteeDID : ValidDID
  /-- クレームの表示ラベル（人間向け） -/
  label : String
  /-- JSON Schema（正式な定義） -/
  claimSchema : Schema
  /-- 最大委任階層数（1以上の自然数） -/
  maxDepth : Nat

-- Reprインスタンスを手動定義（Schema型のReprがないため）
instance : Repr DelegationContent where
  reprPrec d _ :=
    let grantorStr := repr d.grantorDID
    let granteeStr := repr d.granteeDID
    s!"⟨grantorDID: {grantorStr}, granteeDID: {granteeStr}, \
       label: \"{d.label}\", maxDepth: {d.maxDepth}⟩"

namespace DelegationContent

/-- maxDepthが有効かどうかを判定（1以上であること） -/
def isValidMaxDepth (d : DelegationContent) : Bool :=
  d.maxDepth ≥ 1

/-- DelegationContentの等価性判定（DID比較用） -/
def beq (d1 d2 : DelegationContent) : Bool :=
  d1.grantorDID == d2.grantorDID &&
  d1.granteeDID == d2.granteeDID &&
  d1.label == d2.label &&
  d1.maxDepth == d2.maxDepth

instance : BEq DelegationContent where
  beq := beq

end DelegationContent

-- ## Section 5.2: W3C Proof型の定義

/-- W3C Proof構造（簡略版）

    実際のW3C.Proof型は別モジュールで定義されていますが、
    ここでは型定義のために簡略版を使用します。
-/
structure W3CProof where
  /-- 検証メソッド（公開鍵へのリファレンス） -/
  verificationMethod : String
  /-- 署名値 -/
  proofValue : String
  deriving Repr, BEq

-- ## Section 5.3: DelegationChain型

/-- 委任チェーン（Delegation Chain）- N階層対応

    複数の委任を連鎖させた構造。

    **設計思想:**
    - delegations: 委任のリスト（順序重要：[0]が初代、[n]が最終）
    - chainProofs: 各委任に対応する署名リスト（同じ長さ）
    - 循環委任の検出が可能（DID重複チェック）
    - 単調減少性により無限階層を防止
-/
structure DelegationChain where
  /-- 委任のリスト（[0]が初代、[n]が最終） -/
  delegations : List DelegationContent
  /-- 各委任に対応する署名リスト（delegationsと同じ長さ） -/
  chainProofs : List W3CProof
  deriving Repr

namespace DelegationChain

/-- 委任チェーン内のすべてのDIDを取得 -/
def getAllDIDs (chain : DelegationChain) : List ValidDID :=
  chain.delegations.flatMap fun d => [d.grantorDID, d.granteeDID]

/-- 循環委任チェック（DID重複がないことを確認）

    **アルゴリズム:**
    - すべてのDID（grantorDIDとgranteeDID）を抽出
    - 重複があればtrue（循環委任）、なければfalse

    **計算量:** O(n²) where n = DIDs数
-/
def hasCircularDelegation (chain : DelegationChain) : Bool :=
  let allDIDs := getAllDIDs chain
  allDIDs.length != allDIDs.eraseDups.length

/-- 委任チェーンの深さ（委任の数） -/
def depth (chain : DelegationChain) : Nat :=
  chain.delegations.length

/-- 次の階層の残り深さを計算

    **計算式:**
    nextDepth = min(parentDepth - 1, delegationMaxDepth)

    **単調減少性:**
    - parentDepth = 0の場合: nextDepth = 0（これ以上委任不可）
    - それ以外: parentDepth-1とmaxDepthの小さい方

    **例:**
    - computeNextDepth 5 3 = min(4, 3) = 3
    - computeNextDepth 2 5 = min(1, 5) = 1
    - computeNextDepth 0 5 = 0
-/
def computeNextDepth (parentDepth : Nat) (delegationMaxDepth : Nat) : Nat :=
  if parentDepth = 0 then
    0
  else
    min (parentDepth - 1) delegationMaxDepth

/-- 委任チェーンの検証（再帰的、Nat単調減少で停止性保証）

    **パラメータ:**
    - delegations: 検証する委任のリスト
    - remainingDepth: 現在の残り深さ
    - trustedAnchors: 信頼されたDIDのリスト

    **検証ロジック:**
    1. delegationsが空の場合: true（検証成功）
    2. remainingDepth=0の場合: false（深さ超過）
    3. 先頭のdelegationを取り出し：
       - grantorDIDがtrustedAnchorsに含まれるか確認
       - nextDepthを計算（単調減少）
       - 残りのdelegationsを再帰的に検証

    **停止性:**
    remainingDepthが0になるか、delegationsが空になるまで必ず減少する。
    Natの単調減少により、有限回で必ず停止する。
-/
def verifyChain
    (delegations : List DelegationContent)
    (remainingDepth : Nat)
    (trustedAnchors : List ValidDID) : Bool :=
  match remainingDepth with
  | 0 =>
      -- 深さ0の場合、委任が残っていれば無効
      delegations.isEmpty
  | depth + 1 =>
      match delegations with
      | [] => true  -- 空のチェーンは有効
      | d :: ds =>
          -- 初代grantorがtrustedAnchorsに含まれるか
          if !trustedAnchors.contains d.grantorDID then
            false
          else
            -- 次の深さを計算（単調減少）
            let nextDepth := computeNextDepth depth d.maxDepth
            -- 残りを再帰的に検証
            verifyChain ds nextDepth trustedAnchors
termination_by remainingDepth
decreasing_by
  simp_wf
  unfold computeNextDepth
  split
  · omega
  · omega

/-- 委任チェーン全体の検証

    **パラメータ:**
    - chain: 検証する委任チェーン
    - trustedAnchors: 信頼されたDIDのリスト

    **検証内容:**
    1. 循環委任チェック
    2. 委任チェーンの検証（verifyChain使用）

    **初期深さ:**
    InitialMaxDepthを初期remainingDepthとして使用。
    実際の制限は各delegationのmaxDepthで決まる。
-/
def verify (chain : DelegationChain) (trustedAnchors : List ValidDID) : Bool :=
  if hasCircularDelegation chain then
    false
  else
    verifyChain chain.delegations InitialMaxDepth trustedAnchors

end DelegationChain

-- ## Section 5.4: Claim型

/-- クレーム（Claim）- 属性VCに含まれる個々のクレーム

    **設計思想:**
    - 各クレームは自己完結構造（content + delegation chain + proofs）
    - 0階層（直接発行）: contentのみ
    - N階層（委譲発行）: content + delegationChain + contentProof
    - contentProofは最終発行者によるcontentへの署名でZKP検証時にHolderの改ざんを検出

    **フィールド:**
    - content: クレームの実データ（ZKPの入力となる）
    - delegationChain: 委任チェーン（N階層の場合のみ）
    - contentProof: 最終発行者によるcontentへの署名（N階層の場合のみ、ZKP検証に必要）
-/
structure Claim where
  /-- クレームの実データ -/
  content : String  -- 実際にはJSONValue型を使用するが、ここでは簡略化
  /-- 委任チェーン（None=直接発行、Some=委譲発行） -/
  delegationChain : Option DelegationChain
  /-- 最終発行者によるcontentへの署名（ZKP検証に必要） -/
  contentProof : Option W3CProof
  deriving Repr

namespace Claim

/-- 0階層（直接発行）のクレームを構築 -/
def makeDirectClaim (content : String) : Claim :=
  { content, delegationChain := none, contentProof := none }

/-- N階層（委譲発行）のクレームを構築 -/
def makeDelegatedClaim
    (content : String)
    (chain : DelegationChain)
    (contentProof : W3CProof) : Claim :=
  { content,
    delegationChain := some chain,
    contentProof := some contentProof }

/-- クレームが委譲発行かどうか判定 -/
def isDelegated (claim : Claim) : Bool :=
  claim.delegationChain.isSome

/-- クレームの委任階層数を取得

    **戻り値:**
    - 0: 直接発行
    - N: N階層の委任チェーン
-/
def depth (claim : Claim) : Nat :=
  match claim.delegationChain with
  | none => 0
  | some chain => chain.depth

/-- クレームの検証

    **パラメータ:**
    - claim: 検証するクレーム
    - trustedAnchors: 信頼されたDIDのリスト

    **検証内容:**
    - 直接発行: 常にtrue（issuer検証は別途実施）
    - 委譲発行: delegationChainを検証
-/
def verify (claim : Claim) (trustedAnchors : List ValidDID) : Bool :=
  match claim.delegationChain with
  | none => true  -- 直接発行は常に有効（issuer検証は別途）
  | some chain => chain.verify trustedAnchors

end Claim

-- ## Phase 3: 基本的な定理と証明

/-- Theorem: computeNextDepthは単調減少

    parentDepth > 0の場合、computeNextDepthの結果は必ずparentDepthより小さい。
    これにより、有限回の適用でゼロに到達することが保証される。
-/
theorem computeNextDepth_decreasing :
  ∀ (parentDepth maxDepth : Nat),
    parentDepth > 0 →
    DelegationChain.computeNextDepth parentDepth maxDepth < parentDepth := by
  intro parentDepth maxDepth h
  unfold DelegationChain.computeNextDepth
  split
  · omega  -- parentDepth = 0 だが h: parentDepth > 0 なので矛盾
  · omega  -- min (parentDepth - 1) maxDepth < parentDepth

/-- Theorem: verifyChainは有限回で停止

    verifyChainは remainingDepth を単調減少させるため、有限回で必ず停止する。
    これはtermination_by remainingDepthで自動的に保証されている。
-/
theorem verifyChain_terminates :
  ∀ (delegations : List DelegationContent)
    (remainingDepth : Nat)
    (trustedAnchors : List ValidDID),
  ∃ (result : Bool),
    DelegationChain.verifyChain delegations remainingDepth trustedAnchors = result := by
  intro delegations remainingDepth trustedAnchors
  exact ⟨DelegationChain.verifyChain delegations remainingDepth trustedAnchors, rfl⟩

/-- 補助定理: verifyChainの長さ上限

    verifyChainがtrueを返す場合、委任リストの長さはremainingDepth以下である。

    **証明戦略:**
    `verifyChain`の構造を利用し、再帰的に証明する。
    各ステップで、`computeNextDepth`により`remainingDepth`が減少することを使う。
-/
lemma verifyChain_length_bound (delegations : List DelegationContent)
    (remainingDepth : Nat)
    (trustedAnchors : List ValidDID) :
  DelegationChain.verifyChain delegations remainingDepth trustedAnchors = true →
  delegations.length ≤ remainingDepth := by
  -- remainingDepthによる帰納法
  match remainingDepth with
  | 0 =>
      intro h_verify
      unfold DelegationChain.verifyChain at h_verify
      cases delegations with
      | nil => simp
      | cons d ds =>
          simp [List.isEmpty] at h_verify
  | depth + 1 =>
      intro h_verify
      unfold DelegationChain.verifyChain at h_verify
      cases delegations with
      | nil => simp
      | cons d ds =>
          simp at h_verify
          -- simpによりh_verifyは ∧ の形に分解されている
          -- h_verify.1 : d.grantorDID ∈ trustedAnchors
          -- h_verify.2 : verifyChain ds (computeNextDepth depth d.maxDepth) trustedAnchors = true
          -- computeNextDepth depth d.maxDepth ≤ depth を利用
          have h_next_le : DelegationChain.computeNextDepth depth d.maxDepth ≤ depth := by
            unfold DelegationChain.computeNextDepth
            split <;> omega
          -- 再帰的に補助定理を適用
          have h_rec := verifyChain_length_bound ds
            (DelegationChain.computeNextDepth depth d.maxDepth) trustedAnchors h_verify.2
          simp [List.length]
          omega
termination_by remainingDepth
decreasing_by
  simp_wf
  omega

/-- Theorem: 委任チェーンの深さは有限

    verifyChainがtrueを返す場合、委任チェーンの長さは
    initialDepth以下であることが保証される。

    **証明:**
    補助定理verifyChain_length_boundから直接導かれる。
-/
theorem finite_delegation_chain :
  ∀ (delegations : List DelegationContent)
    (initialDepth : Nat)
    (trustedAnchors : List ValidDID),
  DelegationChain.verifyChain delegations initialDepth trustedAnchors = true →
  delegations.length ≤ initialDepth := by
  intro delegations initialDepth trustedAnchors h_verify
  exact verifyChain_length_bound delegations initialDepth trustedAnchors h_verify
