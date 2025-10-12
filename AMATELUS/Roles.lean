/-
# Wallet とRole の定義

このファイルは、AMATELUSプロトコルのWallet、Role（Holder、Issuer、Verifier等）、
および関連する安全性定理を含みます。
-/

import AMATELUS.DID
import AMATELUS.VC
import AMATELUS.ZKP

-- ## Wallet and Role Definitions

/-- 1つのDIDアイデンティティを表す構造体

    Walletは複数のアイデンティティを保持でき、ユーザーは任意にいくつでもDIDを発行できる。
    各アイデンティティは、DID、DIDドキュメント、秘密鍵の組として表現される。

    **設計思想:**
    - Walletは「自分が所有・管理する検証済みデータ」を格納する
    - したがって、IdentityはValidDIDとValidDIDDocumentを使用する
    - 外部から受け取ったDIDはUnknownDIDとして受け取り、検証後にValidDIDに変換してからWalletに保存する
-/
structure Identity where
  did : ValidDID
  didDocument : ValidDIDDocument
  secretKey : SecretKey
  deriving Repr

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
  subject : UnknownDID
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
  trustees : List UnknownDID  -- このトラストアンカーから認証を受けた受託者のリスト
  claimDefinitions : List ClaimDefinitionVC  -- トラストアンカーが定義したクレームのリスト

namespace TrustAnchorInfo

/-- トラストアンカー情報が正規かどうかを検証

    トラストアンカーのValidDIDとValidDIDDocumentが一致することを確認する。

    **設計思想:**
    - TrustAnchorDictがValidDIDをキーとして使用するため、型レベルでDIDの正規性が保証される
    - この関数は、ValidDIDがinfo.didDocumentから正しく生成されたかを検証する
-/
def isValid (anchorDID : ValidDID) (info : TrustAnchorInfo) : Prop :=
  anchorDID = UnknownDID.fromValidDocument info.didDocument

/-- Theorem: 正規のトラストアンカー情報はDID検証に成功する -/
theorem valid_info_passes_did_verification :
  ∀ (anchorDID : ValidDID) (info : TrustAnchorInfo),
    isValid anchorDID info →
    UnknownDID.isValid (UnknownDID.valid anchorDID) info.didDocument := by
  intro anchorDID info h
  unfold isValid at h
  unfold UnknownDID.isValid
  rw [h]

end TrustAnchorInfo

/-- トラストアンカー辞書の型

    辞書: { トラストアンカーのValidDID ↦ TrustAnchorInfo }

    連想リストとして実装され、ValidDIDをキーとしてTrustAnchorInfoを取得できる。

    **設計思想:**
    - トラストアンカーは政府機関や認定認証局など、公的に信頼される存在
    - ValidDIDを使用することで、型レベルで検証済みであることを保証
    - TrustAnchorInfoにValidDIDDocumentが含まれるため、整合性が保証される
-/
abbrev TrustAnchorDict := List (ValidDID × TrustAnchorInfo)

namespace TrustAnchorDict

/-- 辞書からトラストアンカー情報を検索 -/
def lookup (dict : TrustAnchorDict) (anchorDID : ValidDID) : Option TrustAnchorInfo :=
  List.lookup anchorDID dict

/-- 辞書にトラストアンカー情報を追加 -/
def insert (dict : TrustAnchorDict) (anchorDID : ValidDID)
    (info : TrustAnchorInfo) : TrustAnchorDict :=
  (anchorDID, info) :: List.filter (fun (did, _) => did ≠ anchorDID) dict

/-- 辞書から受託者を追加

    指定されたトラストアンカーの受託者リストに新しい受託者を追加する。
-/
def addTrustee (dict : TrustAnchorDict) (anchorDID : ValidDID)
    (trusteeDID : UnknownDID) : TrustAnchorDict :=
  List.map (fun (did, info) =>
    if did = anchorDID then
      (did, { info with trustees := trusteeDID :: info.trustees })
    else
      (did, info)) dict

/-- 辞書内のすべてのエントリーが正規かどうかを検証 -/
def allValid (dict : TrustAnchorDict) : Prop :=
  ∀ (anchorDID : ValidDID) (info : TrustAnchorInfo),
    (anchorDID, info) ∈ dict →
    TrustAnchorInfo.isValid anchorDID info

end TrustAnchorDict

/-- Walletはユーザーの秘密情報を安全に保管する

    ユーザーは任意にいくつでもDIDを発行でき、Walletは複数のアイデンティティを保持する。
    各アイデンティティは独立したDID、DIDドキュメント、秘密鍵の組として管理される。

    **設計思想:**
    - Walletは「自分が所有・管理する検証済みデータ」を格納する
    - したがって、credentialsはValidVCのみを格納する
    - 外部から受け取ったVCはUnknownVCとして受け取り、検証後にValidVCに変換してからWalletに保存する
-/
structure Wallet where
  -- 保持する複数のアイデンティティ
  -- ユーザーは任意にいくつでもDIDを発行できる
  identities : List Identity

  -- 保管されている資格情報（検証済みのみ）
  credentials : List ValidVC

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
def containsDID (wallet : Wallet) (did : ValidDID) : Bool :=
  wallet.identities.any (fun identity => identity.did == did)

/-- WalletからDIDに対応するIdentityを取得する -/
def getIdentity (wallet : Wallet) (did : ValidDID) : Option Identity :=
  wallet.identities.find? (fun identity => identity.did == did)

/-- WalletにDIDが含まれていることを表す命題 -/
def hasDID (wallet : Wallet) (did : ValidDID) : Prop :=
  ∃ (identity : Identity), identity ∈ wallet.identities ∧ identity.did = did

/-- Identityが正規かどうかを検証する述語

    正規のIdentityは以下の条件を満たす：
    1. identity.did = fromValidDocument identity.didDocument

    この検証により、悪意のあるHolderが不正な(did, didDocument)ペアを
    Walletに挿入することを防ぐ。

    **設計思想:**
    - IdentityはValidDIDとValidDIDDocumentを使用するため、型レベルで検証済み
    - この述語は、ValidDIDがValidDIDDocumentから正しく生成されたかを確認
-/
def isValidIdentity (identity : Identity) : Prop :=
  identity.did = UnknownDID.fromValidDocument identity.didDocument

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
    identity.did = UnknownDID.fromValidDocument identity.didDocument := by
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
  expectedTrustAnchor : UnknownDID
  verifierDID : UnknownDID
  verifierCredentials : List UnknownVC
  nonce2 : Nonce
  authProof : UnknownZKP

namespace VerifierAuthMessage

/-- 検証者認証メッセージを検証する関数

    Holderの視点で、検証者認証メッセージが正当かどうかを検証する。

    検証項目:
    1. expectedTrustAnchorがHolderのWallet内の信頼するトラストアンカーに存在する
    2. verifierCredentialsに少なくとも1つのVerifierVCが含まれる
    3. すべてのVerifierVCが有効である（UnknownVC.isValid）
    4. すべてのVerifierVCのissuerがexpectedTrustAnchorと一致する
    5. すべてのVerifierVCのsubjectがverifierDIDと一致する
    6. authProofが有効である（ZeroKnowledgeProof.isValid）
-/
def validateVerifierAuth (msg : VerifierAuthMessage) (holderWallet : Wallet) : Prop :=
  -- 1. expectedTrustAnchorがValidDIDであり、Wallet内の信頼するトラストアンカーに存在する
  (∃ (validDID : ValidDID),
    msg.expectedTrustAnchor = UnknownDID.valid validDID ∧
    (TrustAnchorDict.lookup holderWallet.trustedAnchors validDID).isSome) ∧
  -- 2. verifierCredentialsに少なくとも1つのVerifierVCが含まれる
  msg.verifierCredentials.length > 0 ∧
  -- 3-5. すべてのVerifierVCが以下の条件を満たす
  (∀ vc ∈ msg.verifierCredentials,
    -- VCが有効である
    UnknownVC.isValid vc ∧
    -- VCの発行者がexpectedTrustAnchorと一致する
    UnknownVC.getIssuer vc = msg.expectedTrustAnchor ∧
    -- VCのsubjectがverifierDIDと一致する
    UnknownVC.getSubject vc = msg.verifierDID) ∧
  -- 6. authProofが有効である
  ∃ (relation : Relation), UnknownZKP.isValid msg.authProof relation

end VerifierAuthMessage

namespace VerifierAuthMessage

/-- Theorem: 正規の検証者は検証に成功する

    トラストアンカーから正当に発行されたVerifierVCを持ち、
    有効なZKPを提示する検証者は、Holderの検証を通過する。
-/
theorem authentic_verifier_passes :
  ∀ (msg : VerifierAuthMessage) (holderWallet : Wallet) (validDID : ValidDID),
    -- 前提条件: expectedTrustAnchorがValidDIDである
    msg.expectedTrustAnchor = UnknownDID.valid validDID →
    -- 前提条件: Holderがexpectedトラストアンカーを信頼している
    (TrustAnchorDict.lookup holderWallet.trustedAnchors validDID).isSome →
    -- 前提条件: verifierCredentialsが空でない
    msg.verifierCredentials ≠ [] →
    -- 前提条件: すべてのVerifierVCが正規に発行されている
    (∀ vc ∈ msg.verifierCredentials,
      UnknownVC.isValid vc ∧
      UnknownVC.getIssuer vc = msg.expectedTrustAnchor ∧
      UnknownVC.getSubject vc = msg.verifierDID) →
    -- 前提条件: authProofが有効
    (∃ (relation : Relation), UnknownZKP.isValid msg.authProof relation) →
    -- 結論: 検証に成功する
    validateVerifierAuth msg holderWallet := by
  intro msg holderWallet validDID h_valid h_isSome h_ne h_vcs h_zkp
  -- validateVerifierAuthの定義を展開
  unfold validateVerifierAuth
  -- 4つの連言を構築
  constructor
  · -- 条件1: ValidDIDが存在し、lookupがisSome
    refine ⟨validDID, h_valid, h_isSome⟩
  constructor
  · -- 条件2: length > 0
    exact list_length_pos_of_forall_mem msg.verifierCredentials
      (fun vc => UnknownVC.isValid vc ∧
        UnknownVC.getIssuer vc = msg.expectedTrustAnchor ∧
        UnknownVC.getSubject vc = msg.verifierDID)
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
    -- 条件1: expectedTrustAnchorがInvalidDIDまたは信頼されていないトラストアンカー
    ((match msg.expectedTrustAnchor with
      | UnknownDID.valid validDID =>
          (TrustAnchorDict.lookup holderWallet.trustedAnchors validDID).isNone
      | UnknownDID.invalid _ => True) ∨
     -- 条件2-4: 不正なVerifierVC
     (∃ vc ∈ msg.verifierCredentials,
       ¬UnknownVC.isValid vc ∨
       UnknownVC.getIssuer vc ≠ msg.expectedTrustAnchor ∨
       UnknownVC.getSubject vc ≠ msg.verifierDID) ∨
     -- 条件5: 無効なZKP
     (∀ (relation : Relation), ¬UnknownZKP.isValid msg.authProof relation)) →
    -- 結論: 検証に失敗する
    ¬validateVerifierAuth msg holderWallet := by
  intro msg holderWallet h_bad
  unfold validateVerifierAuth
  intro ⟨⟨validDID, h_valid, h_isSome⟩, h_len, h_vcs, h_zkp⟩
  -- h_badは3つの場合のいずれか
  cases h_bad with
  | inl h_isNone =>
      -- Case 1: InvalidDIDまたはisNone → 矛盾
      rw [h_valid] at h_isNone
      -- match式を簡約
      simp at h_isNone
      -- h_isNoneとh_isSomeは矛盾
      simp [Option.isNone_iff_eq_none, Option.isSome_iff_exists] at h_isNone h_isSome
      obtain ⟨_, h_eq⟩ := h_isSome
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
  trustedRoots : List UnknownDID
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
  issuerCredential : UnknownVC
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

namespace UnknownDID

/-- Theorem: Holderが提示する正規のDIDDocumentは検証に成功する（完全性）

    HolderがWallet内の正規のDID-ValidDIDDocumentペアを提示した場合、
    Verifierの検証は必ず成功する。

    この定理は、Holder構造体の不変条件（wallet_valid）により保証される。

    **設計思想:**
    - IdentityはValidDIDとValidDIDDocumentを使用するため、型レベルで検証済み
    - Wallet.isValidにより、identity.did = fromValidDocument identity.didDocumentが保証される
    - したがって、UnknownDID.isValidは常にtrueを返す
-/
theorem holder_valid_pair_passes :
  ∀ (holder : Holder) (identity : Identity),
    identity ∈ holder.wallet.identities →
    isValid (UnknownDID.valid identity.did) identity.didDocument := by
  intro holder identity h_mem
  unfold isValid
  -- Holder構造体の不変条件により、identity.did = fromValidDocument identity.didDocument
  have h_eq := Wallet.valid_wallet_identity_consistency holder.wallet identity
    holder.wallet_valid h_mem
  -- h_eqを使ってgoalを書き換える
  -- UnknownDID.valid identity.did = UnknownDID.fromValidDocument identity.didDocument
  -- この式は h_eq から直接従う（両辺をUnknownDID.validで包むだけ）
  simp only [h_eq]

end UnknownDID

-- ## プロトコルの安全性

/-- Theorem: Verifierの暗号的健全性（Cryptographic Soundness）

    Verifierは暗号的に検証可能な情報のみを信頼し、
    Wallet実装の詳細には依存しない。

    **設計思想の形式化:**
    - Verifierは以下のみを検証する:
      1. ZKPの暗号的検証（ZeroKnowledgeProof.verify）
      2. VCの署名検証（UnknownVC.isValid）
      3. トラストアンカーチェーンの検証
    - Wallet内部の実装、秘密鍵の管理方法、ZKP生成アルゴリズムは検証しない
    - したがって、Walletバグは検証結果に影響しない（バグがあれば検証失敗）

    **証明の要点:**
    ZKPが有効であることは、ZeroKnowledgeProof.isValidの定義により、
    ZeroKnowledgeProof.verifyがtrueを返すことと同値である。
    この検証は暗号的検証のみに基づき、Wallet実装に依存しない。
-/
theorem verifier_cryptographic_soundness :
  ∀ (_verifier : Verifier) (zkp : UnknownZKP) (relation : Relation),
    -- Verifierの検証: ZKPの暗号的検証のみ
    UnknownZKP.isValid zkp relation →
    -- 結論: この検証はWallet実装に依存しない（暗号的検証のみ）
    UnknownZKP.verify zkp relation = true := by
  intro _verifier zkp relation h_valid
  unfold UnknownZKP.isValid at h_valid
  exact h_valid

/-- Theorem: プロトコルの健全性（Protocol Soundness）

    AMATELUSプロトコル全体の健全性:
    - 正規のHolderは検証に成功する（完全性）
    - 不正なHolderは検証に失敗する（健全性）

    これにより、以下が保証される:
    1. 自己責任の明確化: Wallet選択、操作、デバイス故障は利用者の責任
    2. 暗号的信頼: 悪意ある他者とは暗号理論の範囲でのみ信頼
-/
theorem protocol_soundness :
  -- 1. 完全性: 正規のHolderは検証成功
  (∀ (holder : Holder) (identity : Identity),
    identity ∈ holder.wallet.identities →
    UnknownDID.isValid (UnknownDID.valid identity.did) identity.didDocument) ∧
  -- 2. 健全性: 不正なペアは検証失敗
  (∀ (did : UnknownDID) (doc : ValidDIDDocument),
    UnknownDID.isInvalidPair did doc →
    ¬UnknownDID.isValid did doc) := by
  constructor
  · -- 完全性
    intro holder identity h_mem
    exact UnknownDID.holder_valid_pair_passes holder identity h_mem
  · -- 健全性
    intro did doc h_invalid
    exact UnknownDID.invalid_pair_fails_validation did doc h_invalid
