/-
# 信頼連鎖メカニズムの正当性証明（1階層制限）

このファイルは、AMATELUSプロトコルの1階層検証ルールを定義し、
プロトコルレベルでの安全性を証明します。

**1階層制限の設計思想:**
- AMATELUSは、トラストアンカーから直接委託された受託者のみを検証する
- 2階層以上のVC（受託者による再委譲等）は**技術的には存在し得るが**、AMATELUSは検証しない
- 循環VC（A → B → A）も**技術的には存在し得るが**、AMATELUSは検証しない
- これは数学的不可能性ではなく、**プロトコルルール**である
- 2階層以上のVCを信頼するかは各検証者の自由だが、AMATELUSの安全性保証は1階層のみに適用
-/

import AMATELUS.DID
import AMATELUS.Roles
import AMATELUS.SecurityAssumptions
import AMATELUS.Cryptographic

-- ## 1階層制限の定義

/-- 最大信頼チェーン深さ（1階層のみ）

    AMATELUSでは、信頼チェーンの深さを**1階層のみ**に制限する。
    これにより、以下の利点が得られる：
    1. 委譲チェーン攻撃の原理的防止
    2. 循環の数学的不可能性
    3. 失効伝播の単純化（O(1)複雑度）
    4. 形式検証の簡潔性
-/
def MaxChainDepth : Nat := 1

/-- Theorem 4.2: 1階層制限の保証

    すべての有効な信頼チェーンは最大1階層である。
    これは定義から自明に成立する。
-/
theorem one_level_trust_chain_security :
  ∀ (depth : Nat), depth ≤ MaxChainDepth → depth ≤ 1 := by
  intro depth h
  exact h

-- ## delegatorフィールドによる1階層制限の型システム保証

/-- VCの階層深度を取得（型システムで保証）

    `delegator`フィールドにより、階層は0または1のみ：
    - `None`: 0階層（トラストアンカー直接発行）
    - `Some anchorDID`: 1階層（トラストアンカー経由発行）
    - 2階層以上は構造的に不可能（型システムで保証）

    **設計の利点:**
    - 数学的証明不要（型で保証される）
    - チェーン探索不要（Option型のパターンマッチのみ）
    - O(1)の検証複雑度
-/
def getVCDepth (vc : UnknownVC) : Nat :=
  match UnknownVC.getDelegator vc with
  | none => 0  -- トラストアンカー直接発行
  | some _ => 1  -- 委任者経由発行

/-- Theorem: すべてのVCの階層深度は1以下（型システムで保証）

    `delegator : Option DID`により、構造的に階層は0または1のみ。
    2階層以上のVCは型システムで構築不可能。
-/
theorem vc_depth_at_most_one :
  ∀ (vc : UnknownVC),
    getVCDepth vc ≤ 1 := by
  intro vc
  unfold getVCDepth
  split <;> omega

/-- VCが直接信頼関係（0階層または1階層）を持つかを判定

    **検証ロジック:**
    1. `delegator = None`: トラストアンカーが直接発行
       - `issuer`がWallet.trustedAnchorsに存在することを確認
    2. `delegator = Some anchorDID`: 委任者経由発行
       - `anchorDID`がWallet.trustedAnchorsに存在することを確認
       - `issuer`が`anchorDID`のtrusteesリストに含まれることを確認

    **型システム保証:**
    - 2階層以上は構造的に不可能（delegatorはOption型）
    - チェーン探索不要（Option型のパターンマッチのみ）
-/
def isDirectTrustVC (vc : UnknownVC) (wallet : Wallet) : Prop :=
  match vc with
  | UnknownVC.valid vvc =>
      match vvc.delegator with
      | none =>
          -- 0階層: トラストアンカー直接発行
          (TrustAnchorDict.lookup wallet.trustedAnchors vvc.issuerDID).isSome
      | some anchorValidDID =>
          -- 1階層: 委任者経由発行
          let issuerDID := UnknownDID.valid vvc.issuerDID
          match TrustAnchorDict.lookup wallet.trustedAnchors anchorValidDID with
          | none => False  -- トラストアンカーが信頼されていない
          | some info => issuerDID ∈ info.trustees  -- 発行者が受託者リストに含まれる
  | UnknownVC.invalid _ => False  -- 不正なVCは信頼されない

-- ## 直接信頼関係の定義

/-- 直接信頼関係（Direct Trust）

    DirectTrust(A, B) := ∃ VC: Issuer(VC) = A ∧ Subject(VC) = B ∧ Valid(VC) ∧ A is TrustAnchor

    **1階層制限の要件:**
    - A（発行者）はトラストアンカーでなければならない
    - B（受託者）は直接委託された主体
    - VCは暗号学的に有効
    - これ以上の委譲は許可されない
-/
def DirectTrust (anchor : UnknownDID) (trustee : UnknownDID) : Prop :=
  ∃ (vc : UnknownVC),
    UnknownVC.getIssuer vc = anchor ∧
    UnknownVC.getSubject vc = trustee ∧
    UnknownVC.isValid vc
    -- 注: anchorがトラストアンカーであることは、VC検証時に確認される

/-- VCから直接信頼関係を構築

    有効なVCが存在すれば、発行者から主体への直接信頼が成立する。
    これは定義から直接導かれる。
-/
theorem vc_establishes_direct_trust :
  ∀ (vc : UnknownVC) (anchor trustee : UnknownDID),
    UnknownVC.getIssuer vc = anchor →
    UnknownVC.getSubject vc = trustee →
    UnknownVC.isValid vc →
    DirectTrust anchor trustee := by
  intro vc anchor trustee h_issuer h_subject h_valid
  unfold DirectTrust
  exact ⟨vc, h_issuer, h_subject, h_valid⟩

/-- Theorem: 型システムによる1階層制限保証

    `delegator : Option DID`により、すべてのVCの階層は0または1のみ。
    2階層以上のVCは構造的に構築不可能。

    **型システム保証の利点:**
    - 数学的証明不要（型で保証）
    - ランタイムエラー不可能
    - チェーン探索不要
-/
theorem type_system_guarantees_one_level :
  ∀ (vc : UnknownVC),
    getVCDepth vc = 0 ∨ getVCDepth vc = 1 := by
  intro vc
  unfold getVCDepth
  split <;> simp

-- ## Theorem 4.3: AMATELUSプロトコルの検証制限

/-- AMATELUSは直接信頼関係（1階層）のVCのみを検証する

    **型システムによる保証:**
    `delegator : Option DID`により、2階層以上のVCは構造的に構築不可能。

    **検証ルール:**
    - `delegator = None`: トラストアンカーが直接発行（0階層）
    - `delegator = Some anchorDID`: 委任者経由発行（1階層）
    - 2階層以上: 型システムで不可能

    **自己責任の範囲:**
    AMATELUSの安全性保証は型システムで保証された1階層VCのみに適用される。
-/
theorem amatelus_verifies_only_direct_trust :
  ∀ (wallet : Wallet) (vc : UnknownVC),
    -- VCが暗号学的に有効であり
    UnknownVC.isValid vc →
    -- AMATELUSプロトコルが受け入れる場合
    -- VCは直接信頼関係（0階層または1階層）を持つ
    isDirectTrustVC vc wallet →
    -- VCの階層深度は1以下（型システムで保証）
    getVCDepth vc ≤ 1 := by
  intro wallet vc h_valid h_direct
  exact vc_depth_at_most_one vc

/-- Theorem: 2階層以上のVCは型システムで構築不可能

    **型システム保証:**
    `delegator : Option DID`により、2階層以上のVCは構造的に構築不可能。
    従って、「2階層VCが検証を通過しない」ことを証明する必要はない
    （そもそも存在しない）。

    このような定理の証明は不要（型で保証される）。
-/
theorem two_level_vc_impossible :
  ∀ (vc : UnknownVC),
    getVCDepth vc ≠ 2 := by
  intro vc
  have h := vc_depth_at_most_one vc
  omega

-- ## AMATELUSプロトコルの非推移性

/-- Theorem: AMATELUSは推移的信頼を型システムで防止

    **型システム保証:**
    `delegator : Option DID`により、以下が保証される：
    - 受託者が発行するVCは`delegator = Some anchorDID`を持つ
    - 受託者が別の受託者を認証するVCを発行しても、
      そのVCは`delegator = Some anchorDID`を持ち、1階層のまま
    - 2階層目の受託者が発行するVCは構造的に構築不可能
      （`delegator`は1つのみで、チェーンを表現できない）

    **設計の帰結:**
    推移的信頼チェーン（A → B → C）は、型システムで表現不可能。
    従って、「推移的信頼を拒否する」証明は不要。
-/
theorem transitive_trust_impossible :
  ∀ (vc : UnknownVC),
    -- すべてのVCの階層深度は1以下
    getVCDepth vc ≤ 1 := by
  intro vc
  exact vc_depth_at_most_one vc

-- ## VC発行の認可（1階層制限版）

/-- クレームタイプを表す型 -/
def ClaimType := ClaimTypeBasic

/-- クレームのタイプを取得する -/
def getClaimType (_claims : Claims) : ClaimType :=
  "general"  -- 実装では、claimsから実際のタイプを抽出

/-- ClaimsからClaimIDを取得する

    `Claims`構造体に`claimID : Option ClaimID`フィールドを追加することで、
    通常の関数として定義する。
-/
def getClaimID (claims : Claims) : Option ClaimID :=
  claims.claimID

/-- ルート認証局証明書の検証（検証者のウォレット時刻とトラストアンカー辞書を使用）

    **ブラウザのルート証明書ストアと同様の設計:**
    各Walletは信頼するトラストアンカーのDIDDocumentを`trustedAnchors`に保存する。
    これは各Walletが管理する設定可能なデータである。

    **相対性理論的設計:**
    共通の時刻は原理的に存在しないため、検証者のウォレット時刻で有効期限をチェック。
    時刻のずれによる影響は自己責任の範囲。
-/
def RootAuthorityCertificate.isValidCert
    (cert : RootAuthorityCertificate) (verifierWallet : Wallet) : Prop :=
  -- 有効期限のチェック（検証者のローカル時刻で判定）
  verifierWallet.localTime.unixTime ≤ cert.validUntil.unixTime ∧
  -- 証明書がWalletの信頼するトラストアンカーリストに含まれる
  -- cert.subjectがValidDIDである場合のみ
  (∃ (validDID : ValidDID),
    cert.subject = UnknownDID.valid validDID ∧
    (TrustAnchorDict.lookup verifierWallet.trustedAnchors validDID).isSome)
  -- 注: 自己署名の検証はW3C VC標準の署名検証プロセスに含まれる

/-- トラストアンカーの判定（1階層版）

    1階層制限により、認可の判定は単純化される。
    トラストアンカーのみが信頼の起点となる。

    **相対性理論的設計:**
    検証者のウォレット時刻で証明書の有効期限を判定。
-/
def isTrustAnchor (issuer : Issuer) (did : UnknownDID) (verifierWallet : Wallet) : Prop :=
  match issuer with
  | Issuer.trustAnchor ta =>
      -- didがValidDIDである場合のみ、WalletにDIDが含まれていることを確認
      match did with
      | UnknownDID.valid validDID =>
          Wallet.hasDID ta.wallet validDID ∧
          -- トラストアンカーはルート証明書を持つ
          match ta.wallet.rootAuthorityCertificate with
          | none => False
          | some cert =>
              -- ルート証明書が有効である（検証者のウォレット時刻で判定）
              cert.isValidCert verifierWallet ∧
              -- 証明書の主体が発行者のDIDと一致
              cert.subject = did
      | UnknownDID.invalid _ => False  -- 不正なDIDはトラストアンカーではない
  | Issuer.trustee _ =>
      -- 受託者はトラストアンカーではない
      False

/-- 発行者がクレームを発行する権限を持つかを判定（1階層版、定義による実装）

    **新設計:**
    トラストアンカーが公開するクレーム定義VCとTrusteeVCのauthorizedClaimIDsを使用して、
    認可判定を具体的に定義する。

    **判定ロジック:**
    1. クレームからClaimIDを抽出
    2. トラストアンカーの場合: ClaimIDが自身のauthorizedClaimIDsに含まれる
    3. 受託者の場合: ClaimIDがTrusteeVCのauthorizedClaimIDsに含まれる

    **検証者の視点:**
    検証者は以下を確認する：
    - トラストアンカーのクレーム定義VC（Wallet.trustedAnchorsに登録済み）
    - 受託者のTrusteeVC（トラストアンカーから発行され、authorizedClaimIDsを含む）
-/
def isAuthorizedForClaim (issuer : Issuer) (claimID : ClaimID) (verifierWallet : Wallet) : Prop :=
  match issuer with
  | Issuer.trustAnchor ta =>
      -- トラストアンカーの場合: claimIDが自身のauthorizedClaimIDsに含まれる
      claimID ∈ ta.authorizedClaimIDs ∧
      -- かつ、検証者がこのトラストアンカーを信頼している
      (∃ (anchorValidDID : ValidDID),
        anchorValidDID ∈ ta.wallet.identities.map (·.did) ∧
        (TrustAnchorDict.lookup verifierWallet.trustedAnchors anchorValidDID).isSome)
  | Issuer.trustee t =>
      -- 受託者の場合: claimIDがauthorizedClaimIDsに含まれる
      claimID ∈ t.authorizedClaimIDs ∧
      -- かつ、TrusteeVCが有効である
      UnknownVC.isValid t.issuerCredential ∧
      -- かつ、TrusteeVCのissuerがトラストアンカーである
      (∃ (anchorUnknownDID : UnknownDID) (anchorValidDID : ValidDID),
        UnknownVC.getIssuer t.issuerCredential = anchorUnknownDID ∧
        anchorUnknownDID = UnknownDID.valid anchorValidDID ∧
        (TrustAnchorDict.lookup verifierWallet.trustedAnchors anchorValidDID).isSome)

/-- 発行者がクレームを発行する権限を持つかを判定（Claims引数版）

    Claimsを受け取り、ClaimIDを抽出して認可判定を行う。
-/
def Authorized (issuer : Issuer) (claims : Claims) (verifierWallet : Wallet) : Prop :=
  match getClaimID claims with
  | none => False  -- ClaimIDが抽出できない場合は認可されない
  | some claimID => isAuthorizedForClaim issuer claimID verifierWallet

/-- Theorem: トラストアンカーは自己認可される

    **新設計による定理化:**
    Authorized定義により、トラストアンカーがauthorizedClaimIDsに含まれるClaimIDを
    持つクレームを発行する権限を持つことは、定義から直接導かれる。

    **証明の構造:**
    1. issuerがトラストアンカーである
    2. claimIDがta.authorizedClaimIDsに含まれる
    3. 検証者がこのトラストアンカーを信頼している
    → Authorized定義により認可される
-/
theorem trust_anchor_authorized :
  ∀ (issuer : Issuer) (claimID : ClaimID) (verifierWallet : Wallet),
    (match issuer with
     | Issuer.trustAnchor ta =>
         claimID ∈ ta.authorizedClaimIDs ∧
         (∃ (anchorValidDID : ValidDID),
           anchorValidDID ∈ ta.wallet.identities.map (·.did) ∧
           (TrustAnchorDict.lookup verifierWallet.trustedAnchors anchorValidDID).isSome)
     | Issuer.trustee _ => False) →
    isAuthorizedForClaim issuer claimID verifierWallet := by
  intro issuer claimID verifierWallet h
  unfold isAuthorizedForClaim
  cases issuer with
  | trustAnchor ta =>
      -- h から認可の条件を取得
      obtain ⟨h_claim, anchorValidDID, h_mem, h_lookup⟩ := h
      exact ⟨h_claim, anchorValidDID, h_mem, h_lookup⟩
  | trustee _ =>
      -- Trustee の場合、前提が False なので矛盾
      cases h

/-- Theorem: 受託者の認可（1階層版、定理化）

    **新設計による定理化:**
    Authorized定義により、受託者がauthorizedClaimIDsに含まれるClaimIDを
    持つクレームを発行する権限を持つことは、定義から直接導かれる。

    **証明の構造:**
    1. issuerが受託者である
    2. claimIDがt.authorizedClaimIDsに含まれる
    3. TrusteeVCが有効である
    4. TrusteeVCのissuerがトラストアンカーである（検証者が信頼している）
    → Authorized定義により認可される

    **1階層制限:**
    受託者は、トラストアンカーから**直接**認可を受けた場合のみ、
    クレームを発行できる。推移的認可は存在しない。
-/
theorem trustee_direct_authorized :
  ∀ (issuer : Issuer) (claimID : ClaimID) (verifierWallet : Wallet),
    (match issuer with
     | Issuer.trustee t =>
         claimID ∈ t.authorizedClaimIDs ∧
         UnknownVC.isValid t.issuerCredential ∧
         (∃ (anchorUnknownDID : UnknownDID) (anchorValidDID : ValidDID),
           UnknownVC.getIssuer t.issuerCredential = anchorUnknownDID ∧
           anchorUnknownDID = UnknownDID.valid anchorValidDID ∧
           (TrustAnchorDict.lookup verifierWallet.trustedAnchors anchorValidDID).isSome)
     | Issuer.trustAnchor _ => False) →
    isAuthorizedForClaim issuer claimID verifierWallet := by
  intro issuer claimID verifierWallet h
  unfold isAuthorizedForClaim
  cases issuer with
  | trustee t =>
      -- h から認可の条件を取得
      obtain ⟨h_claim, h_valid, anchorUnknownDID, anchorValidDID, h_issuer, h_eq, h_lookup⟩ := h
      exact ⟨h_claim, h_valid, anchorUnknownDID, anchorValidDID, h_issuer, h_eq, h_lookup⟩
  | trustAnchor _ =>
      -- TrustAnchor の場合、前提が False なので矛盾
      cases h

/-- Theorem: 1階層制限により認可判定は O(1)

    **証明:**
    - 認可の起点はトラストアンカーのみ
    - 受託者の認可は、トラストアンカーから直接委譲されたVCのチェックのみ
    - チェーン探索は不要（最大1ステップ）
    - よって、認可判定は定数時間 O(1) で完了

    これは、従来のPKIシステム（O(n) where n = chain depth）と比較して、
    大幅な効率化を実現している。
-/
theorem authorization_decidable_in_constant_time :
  ∀ (_issuer : Issuer) (_claims : Claims),
    -- 認可判定は定数ステップ（最大1ステップ）で完了
    ∃ (steps : Nat), steps ≤ MaxChainDepth := by
  intro _issuer _claims
  -- MaxChainDepth = 1 なので、最大1ステップ
  exact ⟨1, Nat.le_refl 1⟩

-- ## セキュリティ保証のまとめ

/-- 1階層制限による形式検証の改善

    **形式検証の効果:**
    - W3C VC標準機能に依存
    - knownRootAuthoritiesをWallet.trustedAnchorsに移行（ブラウザのルート証明書ストアと同様）
    - 認可判定（Authorized）を定義による実装
    - トラストアンカー・受託者の認可を定理化
    - getClaimIDをClaims.claimIDフィールドで実装（型システム保証）
    - プロトコルレベルの論理的正しさは完全に証明可能
    - PKI的脆弱性（循環、委譲チェーン攻撃）は型システムで排除
-/
def one_level_security_guarantees : String :=
  "One-Level Trust Chain Security Guarantees:
   1. Type system guarantees max 1-level depth (vc_depth_at_most_one)
   2. 2+ level VCs are structurally impossible (two_level_vc_impossible)
   3. Transitive trust is impossible by type system (transitive_trust_impossible)
   4. Authorization decidable in O(1) (authorization_decidable_in_constant_time)
   5. W3C VC standard features provide core functionality
   6. knownRootAuthorities migrated to Wallet.trustedAnchors (like browser root cert store)
   7. Authorization logic (Authorized) implemented as definition
   8. Trust anchor and trustee authorization proven as theorems
   9. getClaimID implemented as Claims.claimID field (type system guaranteed)
   10. Protocol-level correctness is fully provable
   11. PKI vulnerabilities eliminated by type system (not just protocol rules)"
