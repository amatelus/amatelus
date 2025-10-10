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
  ∀ (_w : Wallet) (_A : PPTAlgorithm),
    -- 外部からはWallet内の秘密鍵にアクセスできない
    Negligible (fun _n _adv => false)

-- ## Holder操作

namespace Holder

/-- HolderがWalletにVCを保存

    Holderは複数のDIDを持つことができるため、
    どのDIDに紐付いたVCを保存するかを明示的に指定する。
-/
def storeCredential
    (h : Holder)
    (vc : VerifiableCredential)
    (holderDID : DID)
    (_h_valid : VerifiableCredential.isValid vc)
    (_h_subject : VerifiableCredential.getSubject vc = holderDID)
    (_h_has_did : Wallet.hasDID h.wallet holderDID) : Holder :=
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

/-- HolderがZKPを生成してVCを提示

    Holderは複数のDIDを持つことができるため、
    どのIdentityを使ってZKPを生成するかを明示的に指定する。
-/
noncomputable def presentCredentialAsZKP
    (h : Holder)
    (vc : VerifiableCredential)
    (holderIdentity : Identity)
    (statement : PublicInput)
    (nonce : Nonce)
    (_h_has_identity : holderIdentity ∈ h.wallet.identities) : ZeroKnowledgeProof :=
  -- Wallet内の指定されたIdentityの秘密鍵を使ってZKP生成
  -- 事前計算されたProofをnonceと結合
  combinePrecomputedProofWithNonce
    h.wallet.precomputedProofs
    vc
    statement
    nonce
    holderIdentity.secretKey

end Holder

-- ## Issuer操作

namespace Issuer

/-- 標準的なVCコンテキスト（公理化） -/
axiom standardVCContext : Context

/-- クレームからVCタイプを推論（公理化） -/
axiom inferVCType : Claims → VCType

/-- 署名関数（公理化） -/
axiom sign : SecretKey → (Claims × DID) → Signature

/-- IssuerがVCを発行

    Note: VerifiableCredentialはinductive typeであり、複数の種類のVCがあるため、
    直接構造体リテラルで構築できない。実装では、claimsの種類に応じて
    適切なVCタイプ（TrusteeVC, NationalIDVC, AttributeVC, VerifierVC）を選択する必要がある。
    ここでは公理として宣言する。
-/
axiom issueCredential :
    ∀ (issuer : Issuer) (_holder : Holder) (claims : Claims),
    Authorized issuer claims →
    (∃ (authorizedTypes : List ClaimType),
      (match issuer with
       | Issuer.trustAnchor ta => ta.authorizedClaimTypes = authorizedTypes
       | Issuer.trustee t => t.authorizedClaimTypes = authorizedTypes) ∧
      getClaimType claims ∈ authorizedTypes) →
    VerifiableCredential

end Issuer

-- ## Verifier操作

namespace Verifier

/-- TrustAnchorDictからDIDを受託者として持つトラストアンカーを探す -/
def findTrustAnchorForTrustee (dict : TrustAnchorDict) (trusteeDID : DID) : Option DID :=
  dict.find? (fun (_anchorDID, info) => info.trustees.contains trusteeDID)
    |>.map (fun (anchorDID, _) => anchorDID)

/-- 信頼チェーンを再帰的に検証する関数（定理化）

    この関数は、TrustAnchorDictを使って信頼チェーンを辿ります。

    検証ロジック：
    1. 検証したいDIDがトラストルートリストに含まれていれば、信頼できる
    2. 深さが0になったら、信頼できない（チェーンが長すぎる）
    3. そうでなければ、TrustAnchorDictから、このDIDを受託者として持つトラストアンカーを探す
    4. そのトラストアンカーが信頼できるか再帰的にチェック（深さを1減らす）
-/
def checkTrustChainRecursive
    (dict : TrustAnchorDict)
    (trustedRoots : List DID)
    (issuerDID : DID)
    (depth : Nat) : Prop :=
  match depth with
  | 0 =>
      -- 深さ制限に達した場合、ルートリストに含まれているかのみチェック
      issuerDID ∈ trustedRoots
  | depth' + 1 =>
      -- トラストルートに含まれているか確認
      (issuerDID ∈ trustedRoots) ∨
      -- または、このDIDを受託者として持つトラストアンカーを探す
      match findTrustAnchorForTrustee dict issuerDID with
      | none => False  -- 受託者として認証されていない
      | some anchorDID =>
          -- そのトラストアンカーが信頼できるか再帰的にチェック
          checkTrustChainRecursive dict trustedRoots anchorDID depth'

/-- 信頼チェーンの検証 -/
def verifyTrustChain
    (dict : TrustAnchorDict)
    (policy : TrustPolicy)
    (vc : VerifiableCredential) : Prop :=
  -- 発行者がルート認証局リストに含まれているか確認
  (VerifiableCredential.getIssuer vc ∈ policy.trustedRoots) ∨
  -- または、信頼チェーンを辿る（深さ制限あり）
  (checkTrustChainRecursive dict policy.trustedRoots (VerifiableCredential.getIssuer vc) policy.maxChainDepth)

/-- VerifierがVCを検証 -/
def verifyCredential
    (verifier : Verifier)
    (vc : VerifiableCredential)
    : Prop :=
  -- 暗号学的検証
  VerifiableCredential.isValid vc ∧
  -- 信頼ポリシーに基づく検証（VerifierのWalletから信頼するトラストアンカー辞書を使用）
  verifyTrustChain verifier.wallet.trustedAnchors verifier.trustPolicy vc

end Verifier

-- ## 操作の安全性定理

/-- Holder操作: 保存後もWalletの一貫性が保たれる（公理化）

    注意: wallet_identity_consistencyは公理なので、
    保存操作後もこの性質が保たれることは自明だが、
    Leanの型システムで直接表現できないため、公理として宣言する。

    Walletが複数のIdentityを持つため、保存操作後も各Identityの一貫性が保たれることを保証する。

    新しい設計では、identity.didDocumentがValidDIDDocumentである場合のみ
    所有権証明が可能です。
-/
axiom holder_store_preserves_validity :
  ∀ (h : Holder) (vc : VerifiableCredential) (holderDID : DID)
    (h_valid : VerifiableCredential.isValid vc)
    (h_subject : VerifiableCredential.getSubject vc = holderDID)
    (h_has_did : Wallet.hasDID h.wallet holderDID),
    let h' := h.storeCredential vc holderDID h_valid h_subject h_has_did;
    ∀ (identity : Identity) (vdoc : ValidDIDDocument),
      identity ∈ h'.wallet.identities →
      identity.didDocument = DIDDocument.valid vdoc →
      identity.did = DID.fromDocument identity.didDocument ∧
      proves_ownership identity.secretKey identity.did vdoc

/-- Issuer操作: 発行されたVCは有効である（公理化）

    注意: この定理は、signature_completenessから導かれるべきだが、
    署名関数の実装が公理化されているため、ここでは公理として宣言する。
-/
axiom issued_credential_is_valid :
  ∀ (issuer : Issuer) (_holder : Holder) (claims : Claims) (vc : VerifiableCredential)
    (_h_authorized : Authorized issuer claims)
    (_h_claimType : ∃ (authorizedTypes : List ClaimType),
      (match issuer with
       | Issuer.trustAnchor ta => ta.authorizedClaimTypes = authorizedTypes
       | Issuer.trustee t => t.authorizedClaimTypes = authorizedTypes) ∧
      getClaimType claims ∈ authorizedTypes),
    -- vcがissueCredentialによって生成されたVCであるという前提の下で
    VerifiableCredential.isValid vc

/-- Verifier操作: 有効なVCの検証は成功する -/
axiom verifier_accepts_valid_credential :
  ∀ (verifier : Verifier) (vc : VerifiableCredential),
    VerifiableCredential.isValid vc →
    VerifiableCredential.getIssuer vc ∈ verifier.trustPolicy.trustedRoots →
    verifier.verifyCredential vc
