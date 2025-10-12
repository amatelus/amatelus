/-
# ZKPのリプレイ攻撃耐性証明

このファイルは、AMATELUSプロトコルのZKP提示におけるリプレイ攻撃耐性を形式的に証明します。
-/

import AMATELUS.DID
import AMATELUS.ZKP
import AMATELUS.Roles
import AMATELUS.SecurityAssumptions
import AMATELUS.Operations

-- ## リプレイ攻撃のモデル

/-- 検証セッションを表す構造体

    各検証セッションは一意のセッション識別子とナンスを持つ。
-/
structure VerificationSession where
  verifier : Verifier
  sessionId : Nat  -- セッション識別子
  nonce : Nonce    -- Verifierが生成したチャレンジナンス
  timestamp : Timestamp  -- セッション開始時刻

/-- ZKP提示の記録

    HolderがVerifierにZKPを提示した記録。
    リプレイ攻撃では、攻撃者がこの記録を盗んで再利用しようとする。

    **注意**: この構造体はリプレイ攻撃の形式化のための補助構造であり、
    実際のプロトコルには存在しません。HolderのDIDやVCは名寄せ回避のため
    ZKPから取り出せないため、Holderフィールドは含めません。
-/
structure ZKPPresentation where
  session : VerificationSession
  zkp : UnknownZKP
  presentedAt : Timestamp

/-- Verifierのナンス履歴

    Verifierは過去に使用したナンスを記録し、同じナンスの再利用を防ぐ。
-/
structure NonceHistory where
  verifier : Verifier
  usedNonces : List Nonce

-- ## ZKPの構造とナンスの性質

/-- 証明したい内容（Statement）

    ZKPで証明する命題を表す。
    例: "私は18歳以上である"、"私は特定のVCを保持している" など

    実装では PublicInput として表現される。
-/
def Statement := PublicInput

/-- ナンスペア: 相互認証における両方のナンス

    相互認証プロトコル（MutualAuthentication.lean）では：
    - nonce1: Holderが生成（Verifierへのチャレンジ）
    - nonce2: Verifierが生成（Holderへのチャレンジ）

    ZKPは両方のナンスを束縛することで、双方の自己責任を実現する。
-/
structure NoncePair where
  holderNonce : Nonce    -- Holderが生成したnonce1
  verifierNonce : Nonce  -- Verifierが生成したnonce2

/-- ZKPの構造的定義（概念レベル）

    **概念レベル**: ZKP = {(nonce1, nonce2), statement}

    ZKPは以下の要素から概念的に構成される：
    1. (nonce1, nonce2): 両方のナンスのペア
       - nonce1: Holderが生成（相互認証時）
       - nonce2: Verifierが生成
    2. statement: 証明したい内容（公開入力）

    **実装レベル**:
    - HolderCredentialZKPCoreに明示的に holderNonce と verifierNonce を格納
    - ZKP生成時に両方のnonceとstatementが暗号学的に束縛される
    - ZKPは特定の秘密鍵で署名されるが、名寄せ回避のためHolderのDIDは
      ZKPから取り出せない設計

    **責任の対称性**:
    - Holderは nonce1 の一意性を保証（自己責任）
    - Verifierは nonce2 の一意性を保証（自己責任）
    - どちらか一方が一意なら、ペア (nonce1, nonce2) は一意
    - よって、相手のバグから自己防衛できる

    この構造により、同じZKPは必ず同じ{(nonce1, nonce2), statement}に束縛される。
-/
def zkpGetNoncePair (zkp : UnknownZKP) : NoncePair :=
  match zkp with
  | UnknownZKP.valid vzkp =>
      match vzkp.zkpType with
      | Sum.inl verifierAuthZKP =>
          -- VerifierAuthZKPの場合、単一のchallengeNonceを両方に使用
          -- （後方互換性のため、プレースホルダとして空のnonceを返す）
          { holderNonce := ⟨[]⟩, verifierNonce := verifierAuthZKP.challengeNonce }
      | Sum.inr holderCredentialZKP =>
          -- HolderCredentialZKPの場合、明示的に格納された両方のnonceを取得
          { holderNonce := holderCredentialZKP.holderNonce,
            verifierNonce := holderCredentialZKP.verifierNonce }
  | UnknownZKP.invalid izkp =>
      match izkp.zkpType with
      | Sum.inl verifierAuthZKP =>
          -- InvalidZKPの場合もプレースホルダ
          { holderNonce := ⟨[]⟩, verifierNonce := verifierAuthZKP.challengeNonce }
      | Sum.inr holderCredentialZKP =>
          -- InvalidZKPでも構造からnonceを取得可能
          { holderNonce := holderCredentialZKP.holderNonce,
            verifierNonce := holderCredentialZKP.verifierNonce }

/-- 後方互換性: 単一のnonce（Verifierのnonce2のみ）を取得

    単方向プロトコル（Holderが一方的に提示）の場合は、
    Verifierのnonce2のみを使用する。
-/
noncomputable def zkpGetNonce (zkp : UnknownZKP) : Nonce :=
  (zkpGetNoncePair zkp).verifierNonce

/-- ZKPから証明内容を取得 -/
def zkpGetStatement (zkp : UnknownZKP) : Statement :=
  (UnknownZKP.getCore zkp).publicInput

/-- ZKPの構造的一意性

    各ZKPは一意の{(nonce1, nonce2), statement}に対応する。
    これは関数の等式性から自明に導かれる。

    Proof: zkp₁ = zkp₂ なら、任意の関数 f に対して f(zkp₁) = f(zkp₂) が成立する。

    **注意**:
    - 名寄せ回避のため、HolderのDIDもZKPから取り出せない
    - リプレイ攻撃の証明には、nonceとstatementの一意性のみが必要
-/
theorem zkp_structure_unique :
  ∀ (zkp₁ zkp₂ : UnknownZKP),
    zkp₁ = zkp₂ →
    zkpGetNoncePair zkp₁ = zkpGetNoncePair zkp₂ ∧
    zkpGetStatement zkp₁ = zkpGetStatement zkp₂ := by
  intro zkp₁ zkp₂ h_eq
  -- zkp₁ = zkp₂ を使って書き換え
  rw [h_eq]
  -- すべて同じzkp₂についての等式なので自明
  exact ⟨rfl, rfl⟩

/-- NoncePairの等号性

    2つのNoncePairが等しい ⟺ 両方のnonceが等しい
-/
theorem nonce_pair_eq :
  ∀ (pair1 pair2 : NoncePair),
    pair1 = pair2 ↔
    (pair1.holderNonce = pair2.holderNonce ∧ pair1.verifierNonce = pair2.verifierNonce) := by
  intro pair1 pair2
  constructor
  · intro h
    rw [h]
    exact ⟨rfl, rfl⟩
  · intro ⟨h_holder, h_verifier⟩
    cases pair1
    cases pair2
    simp at h_holder h_verifier
    simp [h_holder, h_verifier]

/-- どちらか一方のnonceが異なれば、NoncePairも異なる

    これが相互防衛の鍵：
    - Holderが一意なnonce1を生成 → pair全体が一意
    - Verifierが一意なnonce2を生成 → pair全体が一意
    - 相手がバグでnonceを重複させても、自分のnonceが一意なら守られる
-/
theorem nonce_pair_unique_if_either_unique :
  ∀ (pair1 pair2 : NoncePair),
    (pair1.holderNonce ≠ pair2.holderNonce ∨ pair1.verifierNonce ≠ pair2.verifierNonce) →
    pair1 ≠ pair2 := by
  intro pair1 pair2 h_either_diff
  intro h_eq
  rw [nonce_pair_eq] at h_eq
  have ⟨h_holder_eq, h_verifier_eq⟩ := h_eq
  cases h_either_diff with
  | inl h_holder_ne =>
      exact h_holder_ne h_holder_eq
  | inr h_verifier_ne =>
      exact h_verifier_ne h_verifier_eq

/-- ナンスがZKPに束縛されていることを表す述語（後方互換性）

    ZKPがnonceに束縛されている ⟺ ZKPが持つnonceがこのnonceと一致する

    **ZKPの構造的性質による束縛:**
    ZKP生成時にnonceが公開入力に含まれ、zkpGetNonceで取り出せる。
    この構造的性質だけで束縛を定義できる。

    実装では: ZKP生成時にnonceを公開入力に含め、
    証明がこのnonceに対してのみ検証可能になる。

    注: 単方向プロトコル用の定義。Verifierのnonce（nonce2）のみをチェック。
-/
noncomputable def nonceIsBoundToZKP (nonce : Nonce) (zkp : UnknownZKP) : Prop :=
  zkpGetNonce zkp = nonce

/-- ナンスペアがZKPに束縛されていることを表す述語（相互認証用）

    ZKPが(nonce1, nonce2)に束縛されている ⟺
    ZKPが持つナンスペアがこのペアと一致する

    **ZKPの構造的性質による束縛:**
    ZKP生成時に両方のnonceが公開入力に含まれ、zkpGetNoncePairで取り出せる。
    この構造的性質だけで束縛を定義できる。

    **相互防衛の仕組み:**
    - ZKPは構造的に (nonce1, nonce2) のペア全体に束縛される
    - どちらか一方が一意なら、ペア全体が一意
    - よって、各当事者は自分のnonceを一意にすることで自己防衛できる

    実装では:
    - publicInput.data = serialize(claims) || nonce1.value || nonce2.value
    - 両方のnonceが公開入力に含まれる
-/
def noncePairIsBoundToZKP (pair : NoncePair) (zkp : UnknownZKP) : Prop :=
  zkpGetNoncePair zkp = pair

/-- Verifierがナンスを検証する述語

    Verifierは以下を確認する：
    1. ZKPに含まれるナンスが、セッションで発行したナンスと一致すること
    2. このナンスが過去に使用されていないこと
-/
def verifierChecksNonce (session : VerificationSession) (zkp : UnknownZKP)
    (history : NonceHistory) : Prop :=
  -- ナンスがZKPに束縛されている
  nonceIsBoundToZKP session.nonce zkp ∧
  -- ナンスが過去に使用されていない（新鮮性）
  session.nonce ∉ history.usedNonces ∧
  -- Verifierの履歴が正しい
  history.verifier = session.verifier

-- ## リプレイ攻撃のシナリオ

/-- リプレイ攻撃の定義

    攻撃者が以下を試みる：
    1. 正当なHolderの提示を傍受: (session₁, zkp)
    2. 別のセッションで同じZKPを再利用: (session₂, zkp)
       ただし、session₁ ≠ session₂
-/
structure ReplayAttack where
  -- 正当な提示（傍受された）
  originalPresentation : ZKPPresentation

  -- 攻撃者が試みる不正な再利用
  replayedSession : VerificationSession

  -- 元のセッションとは異なる
  differentSession : replayedSession ≠ originalPresentation.session

/-- Theorem: ナンスペア束縛の一意性（ZKPの構造から証明）

    **ZKP = {(nonce1, nonce2), statement} の構造により、一意性が保証される**

    Proof:
    1. ZKPがpair₁に束縛 → zkpGetNoncePair(zkp) = pair₁
    2. ZKPがpair₂に束縛 → zkpGetNoncePair(zkp) = pair₂
    3. 同じzkpから取り出されるペアは一意 → pair₁ = pair₂

    **相互防衛の証明:**
    - もし pair₁.holderNonce ≠ pair₂.holderNonce なら pair₁ ≠ pair₂
    - もし pair₁.verifierNonce ≠ pair₂.verifierNonce なら pair₁ ≠ pair₂
    - よって、どちらか一方が一意なnonceを生成すれば、ペア全体が一意になる
-/
theorem nonce_pair_binding_is_unique :
  ∀ (zkp : UnknownZKP) (pair₁ pair₂ : NoncePair),
    noncePairIsBoundToZKP pair₁ zkp →
    noncePairIsBoundToZKP pair₂ zkp →
    pair₁ = pair₂ := by
  intro zkp pair₁ pair₂ h₁ h₂
  -- noncePairIsBoundToZKP の定義を展開
  unfold noncePairIsBoundToZKP at h₁ h₂
  -- h₁: zkpGetNoncePair zkp = pair₁
  -- h₂: zkpGetNoncePair zkp = pair₂
  -- zkpGetNoncePair zkp は一意に定まる
  -- よって pair₁ = pair₂
  rw [← h₁, h₂]

/-- Theorem: ナンス束縛の一意性（後方互換性）

    **ZKP = {nonce, statement} の構造により、一意性が保証される**

    Proof:
    1. ZKPがnonce₁に束縛 → zkpGetNonce(zkp) = nonce₁
    2. ZKPがnonce₂に束縛 → zkpGetNonce(zkp) = nonce₂
    3. 同じzkpから取り出されるnonceは一意 → nonce₁ = nonce₂

    **重要**: zkpGetNonceが関数であることから、一意性が自明に従う。

    リプレイ攻撃の防止：
    - zkp₁のnonce = nonce₁（構造から一意に定まる）
    - 異なるセッションではnonce₂が使われる（nonce₁ ≠ nonce₂）
    - zkp₁をnonce₂で検証しようとすると: zkpGetNonce(zkp₁) = nonce₁ ≠ nonce₂
    - よってリプレイ攻撃は必ず失敗する

    同じnonceの使いまわし：
    - もし同じnonceを複数セッションで使うと
    - zkpGetNonce(zkp) = nonce が両方で成立
    - よってリプレイ攻撃が成立してしまう（これは防がなければならない）
-/
theorem nonce_binding_is_unique :
  ∀ (zkp : UnknownZKP) (nonce₁ nonce₂ : Nonce),
    nonceIsBoundToZKP nonce₁ zkp →
    nonceIsBoundToZKP nonce₂ zkp →
    nonce₁ = nonce₂ := by
  intro zkp nonce₁ nonce₂ h₁ h₂
  -- nonceIsBoundToZKP の定義を展開
  unfold nonceIsBoundToZKP at h₁ h₂
  -- h₁: zkpGetNonce zkp = nonce₁
  -- h₂: zkpGetNonce zkp = nonce₂
  -- zkpGetNonce zkp は一意に定まる
  -- よって nonce₁ = nonce₂
  rw [← h₁, h₂]

/-- Theorem: 相互防衛の成立（Mutual Defense）

    **どちらか一方が一意なnonceを生成すれば、両者とも守られる**

    これはユーザーの洞察による重要な定理：
    - Holderのウォレットが安全（一意なnonce1） → Verifierのバグから自己防衛
    - Verifierの実装が安全（一意なnonce2） → Holderのバグから自己防衛
    - 両方が一意 → 完全な保護
    - 両方がバグ → お互いに自己責任（プロトコルの責任範囲外）

    Proof:
    - ZKPはペア全体 (nonce1, nonce2) に束縛される
    - どちらか一方が異なれば、ペア全体が異なる
    - よって、異なるセッションでのZKP再利用は不可能
-/
theorem mutual_defense_property :
  ∀ (zkp : UnknownZKP) (pair₁ pair₂ : NoncePair),
    noncePairIsBoundToZKP pair₁ zkp →
    -- もし、どちらか一方のnonceが異なれば
    (pair₁.holderNonce ≠ pair₂.holderNonce ∨ pair₁.verifierNonce ≠ pair₂.verifierNonce) →
    -- ZKPはpair₂に束縛されていない
    ¬noncePairIsBoundToZKP pair₂ zkp := by
  intro zkp pair₁ pair₂ h_bound₁ h_either_diff
  intro h_bound₂
  -- 両方に束縛されているなら、一意性よりpair₁ = pair₂
  have h_eq : pair₁ = pair₂ := nonce_pair_binding_is_unique zkp pair₁ pair₂ h_bound₁ h_bound₂
  -- しかし、nonce_pair_unique_if_either_unique により pair₁ ≠ pair₂
  have h_ne : pair₁ ≠ pair₂ := nonce_pair_unique_if_either_unique pair₁ pair₂ h_either_diff
  -- 矛盾
  exact h_ne h_eq

/-- Corollary: Holderの自己防衛

    Holderが一意なnonce1を生成すれば、Verifierが同じnonce2を使い回しても
    Holderは自己防衛できる。

    例: Holder（ドライバー）が安全なウォレットを使用していれば、
        Verifier（検証アプリ）にバグがあってもドライバーは守られる。
-/
theorem holder_self_defense :
  ∀ (zkp : UnknownZKP) (pair₁ pair₂ : NoncePair),
    noncePairIsBoundToZKP pair₁ zkp →
    -- Holderが異なるnonce1を生成（Verifierは同じnonce2かもしれない）
    pair₁.holderNonce ≠ pair₂.holderNonce →
    -- ZKPはpair₂で検証できない
    ¬noncePairIsBoundToZKP pair₂ zkp := by
  intro zkp pair₁ pair₂ h_bound₁ h_holder_diff
  apply mutual_defense_property zkp pair₁ pair₂ h_bound₁
  left
  exact h_holder_diff

/-- Corollary: Verifierの自己防衛

    Verifierが一意なnonce2を生成すれば、Holderが同じnonce1を使い回しても
    Verifierは自己防衛できる。

    例: Verifier（銀行システム）が適切に実装されていれば、
        Holder（顧客）のウォレットにバグがあっても銀行は守られる。
-/
theorem verifier_self_defense :
  ∀ (zkp : UnknownZKP) (pair₁ pair₂ : NoncePair),
    noncePairIsBoundToZKP pair₁ zkp →
    -- Verifierが異なるnonce2を生成（Holderは同じnonce1かもしれない）
    pair₁.verifierNonce ≠ pair₂.verifierNonce →
    -- ZKPはpair₂で検証できない
    ¬noncePairIsBoundToZKP pair₂ zkp := by
  intro zkp pair₁ pair₂ h_bound₁ h_verifier_diff
  apply mutual_defense_property zkp pair₁ pair₂ h_bound₁
  right
  exact h_verifier_diff

-- ## Theorem: リプレイ攻撃耐性と自己責任の原則

/-- Theorem: 一意のナンスを発行した主体はリプレイ攻撃から自己防衛できる

    **重要な設計思想の明確化:**
    プロトコル自体はリプレイ攻撃を無条件に防ぐわけではない。
    **一意のナンスを発行した主体のみが自己防衛できる。**

    証明の構造（単方向プロトコル用）:
    - 前提条件: 元のセッション（session₁）のnonce₁と異なるセッション（session₂）のnonce₂は異なる
    - ZKPはnonce₁に束縛されている → nonce₂での検証は失敗
    - **責任**: Verifierは一意なnonceを生成する責任がある

    もしVerifierがnonceを重複させた場合（nonce_reuse_enables_replay_attack）:
    - この定理の前提条件が成立しないため、リプレイ攻撃が成立してしまう
    - **これはVerifierの責任であり、プロトコルの責任範囲外**

    **条件付き安全性:**
    - プロトコルは「一意なnonceを発行すれば安全」という保証を提供
    - プロトコルは「必ず一意なnonceが発行される」ことは保証しない
    - 一意性の確保は実装者の自己責任
-/
theorem replay_attack_prevented_by_unique_nonce_generator :
  ∀ (attack : ReplayAttack) (history : NonceHistory),
    -- Verifierが一意のnonceを発行している場合（前提条件）
    attack.originalPresentation.session.nonce ≠ attack.replayedSession.nonce →
    -- 元の提示は正当（ナンス検証に成功）
    verifierChecksNonce attack.originalPresentation.session
                        attack.originalPresentation.zkp
                        history →
    -- リプレイ攻撃は失敗する
    ¬verifierChecksNonce attack.replayedSession
                         attack.originalPresentation.zkp
                         history := by
  intro attack history h_diff_nonce h_original_valid
  unfold verifierChecksNonce at h_original_valid ⊢
  have ⟨h_bound_original, _h_fresh_original, _h_verifier_original⟩ := h_original_valid

  intro ⟨h_bound_replay, _h_fresh_replay, _h_verifier_replay⟩

  -- ZKPのナンス束縛の一意性により、矛盾を導く
  have h_same_nonce : attack.originalPresentation.session.nonce =
                      attack.replayedSession.nonce :=
    nonce_binding_is_unique
      attack.originalPresentation.zkp
      attack.originalPresentation.session.nonce
      attack.replayedSession.nonce
      h_bound_original
      h_bound_replay

  -- h_diff_nonce と h_same_nonce は矛盾
  exact h_diff_nonce h_same_nonce

/-- Theorem: リプレイ攻撃耐性は一意なナンス発行に依存する（条件付き安全性）

    **プロトコルの安全性保証:**
    異なるセッションで異なるnonceを使用している場合のみ、
    リプレイ攻撃は防がれる。

    **責任の所在:**
    - Verifier実装者: 一意なnonceを生成する責任
    - もし重複したnonceを発行すれば、この定理の前提条件が成立せず、
      リプレイ攻撃が成立する（自己責任）
    - プロトコルは「一意なnonceを発行すれば安全」という保証を提供するが、
      「必ず一意なnonceが発行される」ことは保証しない

    **設計思想:**
    「安全な実装を選ぶのはユーザー/実装者の責任」という原則。
    プロトコルは手段を提供するが、実装品質は保証しない。
-/
theorem replay_attack_resistance_conditional :
  ∀ (attack : ReplayAttack) (history : NonceHistory),
    -- 前提: 異なるセッションは異なるnonceを持つ（実装者の責任）
    attack.originalPresentation.session.nonce ≠ attack.replayedSession.nonce →
    verifierChecksNonce attack.originalPresentation.session
                        attack.originalPresentation.zkp
                        history →
    ¬verifierChecksNonce attack.replayedSession
                         attack.originalPresentation.zkp
                         history := by
  intro attack history h_diff_nonce h_original_valid
  exact replay_attack_prevented_by_unique_nonce_generator
    attack history h_diff_nonce h_original_valid

-- ## セキュリティ保証と設計要件

/-- Theorem: 同じnonceの使いまわしによるリプレイ攻撃の成立

    同じVerifierが異なるセッションで同じnonceを使用すると、リプレイ攻撃が成立してしまう。
    これは、ZKPの構造的性質により明確に説明できる：
    - session₁とsession₂で同じnonceを使用
    - zkpはzkpGetNonce(zkp) = nonceを満たす
    - 両方のセッションで nonceIsBoundToZKP nonce zkp が成立
    - よって両方のセッションでzkpが検証に成功する（リプレイ攻撃成立）

    **設計への教訓**: Verifierは各セッションで一意な新しいnonceを生成しなければならない。
-/
theorem nonce_reuse_enables_replay_attack :
  ∀ (zkp : UnknownZKP) (session₁ session₂ : VerificationSession)
    (history : NonceHistory),
    -- 異なるセッションだが同じnonceを使用（設計ミス！）
    session₁ ≠ session₂ →
    session₁.nonce = session₂.nonce →
    -- 両方のセッションが同じVerifierを使用
    session₁.verifier = session₂.verifier →
    session₁.verifier = history.verifier →
    -- session₁で検証成功
    verifierChecksNonce session₁ zkp history →
    -- session₂でも検証成功（リプレイ攻撃成立！）
    verifierChecksNonce session₂ zkp history := by
  intro zkp session₁ session₂ history h_diff_session
    h_same_nonce h_same_verifier h_history_verifier h_verify₁
  unfold verifierChecksNonce at h_verify₁ ⊢
  have ⟨h_bound₁, h_fresh₁, _h_verifier₁⟩ := h_verify₁
  constructor
  · -- ナンス束縛: session₂.nonce = session₁.nonce なので同じ辞書を参照
    unfold nonceIsBoundToZKP at h_bound₁ ⊢
    rw [← h_same_nonce]
    exact h_bound₁
  constructor
  · -- 新鮮性: 同じnonceなので同じチェック
    rw [← h_same_nonce]
    exact h_fresh₁
  · -- Verifierの一致
    rw [← h_same_verifier, h_history_verifier]

/-- Corollary: 一意なnonceを発行するVerifierは攻撃者のZKP再利用を防げる

    **条件付き安全性:**
    Verifierが一意なnonceを発行している場合のみ、
    正当なHolderが生成したZKPを盗んだ攻撃者は、
    別のセッションでそのZKPを使用できない。

    **責任の所在:**
    - Verifier実装者: 一意なnonceを生成する責任
    - もしnonceが重複すれば、攻撃者がZKPを再利用できる（自己責任）

    **二重ナンス束縛による改善:**
    Holderも一意なnonceを生成すれば、Verifierのバグから自己防衛できる。
-/
theorem attacker_cannot_reuse_zkp_if_unique_nonce :
  ∀ (legitimatePresentation : ZKPPresentation)
    (attackerSession : VerificationSession)
    (history : NonceHistory),
    -- 前提: Verifierが一意なnonceを発行している
    legitimatePresentation.session.nonce ≠ attackerSession.nonce →
    -- 正当な提示が成功
    verifierChecksNonce legitimatePresentation.session
                        legitimatePresentation.zkp
                        history →
    -- 攻撃者のセッションは異なる
    attackerSession ≠ legitimatePresentation.session →
    -- 攻撃者の再利用は失敗する
    ¬verifierChecksNonce attackerSession
                         legitimatePresentation.zkp
                         history := by
  intro presentation attackerSession history h_diff_nonce h_legit h_diff_session

  -- ReplayAttackを構成
  let attack : ReplayAttack := {
    originalPresentation := presentation,
    replayedSession := attackerSession,
    differentSession := h_diff_session
  }

  -- replay_attack_prevented_by_unique_nonce_generator を適用
  exact replay_attack_prevented_by_unique_nonce_generator attack history h_diff_nonce h_legit

/-- Corollary: ZKPの一回使用性は一意なnonce発行に依存する

    **条件付き安全性:**
    各ZKPは特定のセッションのナンスに束縛されており、
    **一意なnonceが発行されている場合のみ**、そのセッションでのみ有効である。

    **プロトコルの保証:**
    - プロトコルは「一意なnonceを発行すれば、ZKPは一回のみ使用可能」を保証
    - プロトコルは「必ず一意なnonceが発行される」ことは保証しない
    - 一意性の確保は実装者の責任

    **設計思想:**
    「安全な実装を選ぶのはユーザー/実装者の責任」という原則に基づく。
-/
theorem zkp_is_single_use_if_unique_nonce :
  ∀ (zkp : UnknownZKP) (session₁ session₂ : VerificationSession)
    (history : NonceHistory),
    -- 前提: 異なるセッションは異なるnonceを持つ
    session₁.nonce ≠ session₂.nonce →
    session₁ ≠ session₂ →
    verifierChecksNonce session₁ zkp history →
    ¬verifierChecksNonce session₂ zkp history := by
  intro zkp session₁ session₂ history h_diff_nonce h_diff_session h_session₁

  -- 任意のTimestampを選ぶ（0でよい）
  let someTimestamp : Timestamp := ⟨0⟩

  -- ZKPPresentationを構成（Holderフィールドは不要）
  let presentation : ZKPPresentation := {
    session := session₁,
    zkp := zkp,
    presentedAt := someTimestamp
  }

  -- ReplayAttackを構成
  let attack : ReplayAttack := {
    originalPresentation := presentation,
    replayedSession := session₂,
    differentSession := Ne.symm h_diff_session  -- session₂ ≠ session₁
  }

  -- replay_attack_prevented_by_unique_nonce_generator を適用
  exact replay_attack_prevented_by_unique_nonce_generator attack history h_diff_nonce h_session₁

-- ## 実装への要件

/-- 実装要件: リプレイ攻撃耐性の保証

    ZKPの構造的性質を実現するため、実装は以下を保証する：

    **相互認証プロトコルにおける二重ナンス束縛（Dual Nonce Binding）:**

    相互認証プロトコル（MutualAuthentication.lean）では、ZKPは両方のナンスに束縛される：
    - ZKP構造: {(nonce1, nonce2), statement}
    - 実装: publicInput.data = serialize(claims) || nonce1.value || nonce2.value
    - どちらか一方が一意なら、ペア全体が一意 → 相互防衛が成立

    **相互防衛の実現（mutual_defense_property）:**
    - Holderが一意なnonce1を生成 → Verifierのバグから自己防衛（holder_self_defense）
    - Verifierが一意なnonce2を生成 → Holderのバグから自己防衛（verifier_self_defense）
    - 両方が一意 → 完全な保護
    - 両方がバグ → お互いに自己責任（プロトコルの責任範囲外）

    **Verifier側（プロトコルの必須要件）:**

    Verifierは **必ず** 以下を実装しなければならない：

    1. 各セッションで暗号学的にランダムな一意のnonce（nonce2）を生成
       - セキュアな乱数生成器を使用（/dev/urandom, crypto.randomBytes等）
       - **理由**: 従来はHolder（一般市民）を保護する責任があったが、
                   二重ナンス束縛により、Verifier自身の自己防衛にもなる
       - **責任**: プロトコル設計者・Verifier実装者

    2. 使用済みnonceの記録（nonce履歴）
       - データベースまたはメモリ内キャッシュで管理
       - 古いnonceは定期的にクリーンアップ可能（セッション有効期限後）

    3. ナンス新鮮性の検証
       - ZKP検証前に nonce ∉ usedNonces を確認
       - 検証成功後に nonce を usedNonces に追加

    **Holder側（プロトコルの必須要件）:**

    4. ZKP生成時の二重nonce束縛
       - Holderのnonce1とVerifierのnonce2を両方とも公開入力に含める
       - 証明がこのナンスペアに対してのみ有効になるよう生成
       - 実装: publicInput.data = serialize(claims) || nonce1.value || nonce2.value

    **Holder側（推奨事項、プロトコル責任範囲外）:**

    相互認証プロトコル（MutualAuthentication.lean）において、Holderも
    Verifierにチャレンジを発行する場合：

    5. Holderが生成するnonce（nonce1）（推奨）
       - 一意なnonceを生成することが推奨される
       - **理由**: 二重ナンス束縛により、自己防衛できる
       - もし重複した場合でも、Verifierが一意なnonce2を生成すれば保護される
       - **責任**: Holder（ウォレット選択の責任）
       - 安全なブラウザを選ぶ責任がユーザーにあるように、
         安全なウォレットを選ぶことはHolder自身の責任

    **責任範囲の明確化:**

    | ナンス生成者 | 一意性要件 | 重複時の被害 | 責任の所在 | 防御メカニズム |
    |------------|----------|------------|----------|-------------|
    | Verifier   | **必須** | 従来はHolder全員 | プロトコル | 相手のnonce1で自己防衛可 |
    | Holder     | 推奨のみ | Holder自身のみ | Holder   | 相手のnonce2で自己防衛可 |

    **二重ナンス束縛の利点:**
    - どちらか一方が安全な実装なら、両者とも保護される
    - プロトコルの堅牢性が向上（単一障害点を排除）
    - 責任の対称性（相互自己防衛）

    **セキュリティ保証:**
    - 異なるセッション → 異なるnonce2 → 異なるペア (nonce1, nonce2)
    - zkpGetNoncePair(zkp) = (nonce₁, nonce₁') かつ (nonce₁, nonce₁') ≠ (nonce₂, nonce₂')
    - よってリプレイ攻撃は必ず失敗する（replay_attack_resistance）
    - 相互防衛により、片方のバグがあっても保護される（mutual_defense_property）
-/
def implementationRequirements : String :=
  "Dual Nonce Binding in Mutual Authentication:
   ZKP = {(nonce1, nonce2), statement}
   Implementation: publicInput = serialize(claims) || nonce1 || nonce2

   Mutual Defense Property (mutual_defense_property):
   - If EITHER nonce is unique, BOTH parties are protected
   - Holder generates unique nonce1 → self-defense from Verifier bugs
   - Verifier generates unique nonce2 → self-defense from Holder bugs
   - Both unique → complete protection
   - Both buggy → mutual self-responsibility

   Verifier Requirements (PROTOCOL MANDATORY):
   1. Generate unique random nonce2 (MUST)
   2. Maintain nonce history (usedNonces)
   3. Verify nonce freshness before accepting ZKP
   4. Benefits: Self-defense via dual binding

   Holder Requirements (MANDATORY):
   1. Bind ZKP to BOTH nonces (nonce1 + nonce2)

   Holder Requirements (RECOMMENDED):
   1. Generate unique nonce1 (recommended, not mandatory)
   2. Benefits: Self-defense via dual binding
   3. If nonce1 is reused, Verifier's nonce2 still protects both

   Security Guarantees:
   - replay_attack_resistance: Different sessions → different nonce pairs
   - holder_self_defense: Unique nonce1 protects from Verifier bugs
   - verifier_self_defense: Unique nonce2 protects from Holder bugs
   - No single point of failure in nonce generation"
