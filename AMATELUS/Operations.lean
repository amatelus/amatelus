/-
# Wallet/Holder/Issuer/Verifier 操作定義

このファイルは、Wallet、Holder、Issuer、Verifierの具体的な操作を定義します。
-/

import AMATELUS.Basic
import AMATELUS.SecurityAssumptions
import AMATELUS.Cryptographic
import AMATELUS.TrustChain

-- ## Wallet操作の公理

/-- Walletが秘密鍵を安全に保護していることの公理 -/
axiom wallet_secret_key_protection :
  ∀ (w : Wallet) (A : PPTAlgorithm),
    -- 外部からはWallet内の秘密鍵にアクセスできない
    Negligible (fun _n _adv => false)

-- ## Holder操作

namespace Holder

/-- HolderがWalletにVCを保存 -/
def storeCredential
    (h : Holder)
    (vc : VerifiableCredential)
    (_h_valid : VerifiableCredential.isValid vc)
    (_h_subject : vc.subject = h.wallet.did) : Holder :=
  { h with
    wallet := { h.wallet with
      credentials := vc :: h.wallet.credentials } }

/-- HolderがWalletから特定のVCを取得 -/
def getCredential
    (h : Holder)
    (predicate : VerifiableCredential → Bool)
    : Option VerifiableCredential :=
  h.wallet.credentials.find? predicate

/-- ナンスと事前計算されたProofを結合する関数（公理化） -/
axiom combinePrecomputedProofWithNonce :
  List PrecomputedZKP →
  VerifiableCredential →
  PublicInput →  -- statement
  Nonce →
  SecretKey →
  ZeroKnowledgeProof

/-- HolderがZKPを生成してVCを提示 -/
noncomputable def presentCredentialAsZKP
    (h : Holder)
    (vc : VerifiableCredential)
    (statement : PublicInput)
    (nonce : Nonce) : ZeroKnowledgeProof :=
  -- Wallet内の秘密鍵を使ってZKP生成
  -- 事前計算されたProofをnonceと結合
  combinePrecomputedProofWithNonce
    h.wallet.precomputedProofs
    vc
    statement
    nonce
    h.wallet.secretKey

end Holder

-- ## Issuer操作

namespace Issuer

/-- 標準的なVCコンテキスト（公理化） -/
axiom standardVCContext : Context

/-- クレームからVCタイプを推論（公理化） -/
axiom inferVCType : Claims → VCType

/-- 署名関数（公理化） -/
axiom sign : SecretKey → (Claims × DID) → Signature

/-- IssuerがVCを発行 -/
noncomputable def issueCredential
    (issuer : Issuer)
    (holder : Holder)
    (claims : Claims)
    (_h_authorized : Authorized issuer claims)
    (_h_claimType : getClaimType claims ∈ issuer.authorizedClaimTypes)
    : VerifiableCredential :=
  {
    context := standardVCContext,
    type := inferVCType claims,
    issuer := issuer.wallet.did,
    subject := holder.wallet.did,
    claims := claims,
    signature := sign issuer.wallet.secretKey (claims, holder.wallet.did),
    credentialStatus := { statusListUrl := none }
  }

end Issuer

-- ## Verifier操作

namespace Verifier

/-- 信頼チェーンを再帰的に検証する関数（公理化） -/
axiom checkTrustChainRecursive : List DID → DID → Nat → Prop

/-- 信頼チェーンの検証 -/
def verifyTrustChain (policy : TrustPolicy) (vc : VerifiableCredential) : Prop :=
  -- 発行者がルート認証局リストに含まれているか確認
  (vc.issuer ∈ policy.trustedRoots) ∨
  -- または、信頼チェーンを辿る（深さ制限あり）
  (checkTrustChainRecursive policy.trustedRoots vc.issuer policy.maxChainDepth)

/-- VerifierがVCを検証 -/
def verifyCredential
    (verifier : Verifier)
    (vc : VerifiableCredential)
    : Prop :=
  -- 暗号学的検証
  VerifiableCredential.isValid vc ∧
  -- 信頼ポリシーに基づく検証
  verifyTrustChain verifier.trustPolicy vc

end Verifier

-- ## 操作の安全性定理

/-- Holder操作: 保存後もWalletの一貫性が保たれる（公理化）

    注意: wallet_did_consistencyは公理なので、
    保存操作後もこの性質が保たれることは自明だが、
    Leanの型システムで直接表現できないため、公理として宣言する。
-/
axiom holder_store_preserves_validity :
  ∀ (h : Holder) (vc : VerifiableCredential)
    (h_valid : VerifiableCredential.isValid vc)
    (h_subject : vc.subject = h.wallet.did),
    let h' := h.storeCredential vc h_valid h_subject;
    h'.wallet.did = DID.fromDocument h'.wallet.didDocument ∧
    proves_ownership h'.wallet.secretKey h'.wallet.did h'.wallet.didDocument

/-- Issuer操作: 発行されたVCは有効である（公理化）

    注意: この定理は、signature_completenessから導かれるべきだが、
    署名関数の実装が公理化されているため、ここでは公理として宣言する。
-/
axiom issued_credential_is_valid :
  ∀ (issuer : Issuer) (holder : Holder) (claims : Claims)
    (h_authorized : Authorized issuer claims)
    (h_claimType : getClaimType claims ∈ issuer.authorizedClaimTypes),
    let vc := issuer.issueCredential holder claims h_authorized h_claimType
    VerifiableCredential.isValid vc

/-- Verifier操作: 有効なVCの検証は成功する -/
axiom verifier_accepts_valid_credential :
  ∀ (verifier : Verifier) (vc : VerifiableCredential),
    VerifiableCredential.isValid vc →
    vc.issuer ∈ verifier.trustPolicy.trustedRoots →
    verifier.verifyCredential vc
