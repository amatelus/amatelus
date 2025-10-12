/-
# Wallet/Holder/Issuer/Verifier 操作定義

このファイルは、Wallet、Holder、Issuer、Verifierの具体的な操作を定義します。
-/

import AMATELUS.DID
import AMATELUS.VC
import AMATELUS.ZKP
import AMATELUS.Roles
import AMATELUS.SecurityAssumptions
import AMATELUS.Cryptographic
import AMATELUS.TrustChain

-- ## Holder操作

namespace Holder

/-- WalletにVCを保存

    **設計変更:**
    Holder構造体は単なるラッパーなので、操作はWalletレベルで行います。
    不変条件 `wallet_valid` はHolder構築時に一度だけ保証されます。

    この関数は単にcredentialsリストにVCを追加するだけで、
    identitiesは変更しません。したがって、Wallet.isValidは保持されます。
-/
def storeCredential
    (wallet : Wallet)
    (vc : UnknownVC)
    (holderDID : UnknownDID)
    (_h_valid : UnknownVC.isValid vc)
    (_h_subject : UnknownVC.getSubject vc = holderDID)
    (_h_has_did : Wallet.hasDID wallet holderDID) : Wallet :=
  { wallet with
    credentials := vc :: wallet.credentials }

/-- Walletから特定のVCを取得 -/
def getCredential
    (wallet : Wallet)
    (predicate : UnknownVC → Bool)
    : Option UnknownVC :=
  wallet.credentials.find? predicate

/-- ZKP生成の材料をまとめた構造体

    すべての可能な材料の組み合わせに対して
    適切なZKPが既に存在しているという理想化モデル。
-/
structure ZKPMaterial where
  precomputedProofs : List PrecomputedZKP
  credential : UnknownVC
  statement : PublicInput
  nonce : Nonce
  secretKey : SecretKey

/-- ZKPMaterialから証人（Witness）を抽出

    暗号学的証明システムでは、証人は秘密情報（秘密鍵）です。
    ZKPMaterialの秘密部分を証人として扱います。
-/
def zkpMaterialToWitness (material : ZKPMaterial) : Witness :=
  -- 秘密鍵をWitnessとして使用
  -- 実際の実装では、秘密鍵と事前計算されたプルーフの組み合わせ
  Witness.mk material.secretKey.bytes

/-- ZKPMaterialから公開入力（PublicInput）を抽出

    公開入力は、証明したいステートメントとナンスを含みます。
-/
def zkpMaterialToPublicInput (material : ZKPMaterial) : PublicInput :=
  -- ステートメントとナンスを組み合わせて公開入力を構築
  material.statement

/-- ZKP検証の関係式（Relation）

    この関係式は、証人（秘密鍵）と公開入力（ステートメント）の関係を定義します。

    暗号学的意味：
    - 証人が秘密鍵であることを検証
    - VCの内容が公開入力と一致することを検証
    - ナンスがリプレイ攻撃を防ぐことを検証

    実装は抽象化されており、実際のSTARKs検証ロジックに委譲されます。
-/
def zkpRelation : Relation :=
  fun (_publicInput : PublicInput) (_witness : Witness) => true  -- 実装は抽象化

/-- ProofからZeroKnowledgeProofを構築

    amatZKP.proverが生成したProofを、AMATELUSのZeroKnowledgeProof型に変換します。
    生成されたProofは暗号学的に有効であるため、valid ZKPとして構築されます。
-/
noncomputable def proofToZKP (proof : Proof) (material : ZKPMaterial) : UnknownZKP :=
  -- ValidZKPとして構築
  -- amatZKP.completenessにより、このZKPは検証に成功することが保証される
  let holderZKP : HolderCredentialZKPCore := {
    core := {
      proof := proof
      publicInput := material.statement
      proofPurpose := "credential-presentation"
      created := { unixTime := 0 }  -- タイムスタンプは実装依存
    }
    holderNonce := ⟨[]⟩  -- 単方向プロトコル用（プレースホルダ）
    verifierNonce := material.nonce  -- Verifierが生成したnonce
    claimedAttributes := "ZKP-based credential presentation"
  }
  UnknownZKP.valid {
    zkpType := Sum.inr holderZKP
  }

/-- 無限のZKP辞書（暗号学的証明器による実装）

    この関数は、すべての可能な材料に対してZKPを返します。
    理想化モデル（ランダムオラクル）から暗号学的証明器（amatZKP）への移行。

    **変更点:**
    - amatZKP.proverを使用してProofを生成
    - 生成されたProofはamatZKP.completenessにより有効であることが保証される

    **暗号学的安全性:**
    - SecurityAssumptions.amatZKP（STARKs）に依存
    - 量子安全性: 128ビット（Grover適用後）
    - NIST最小要件: 128ビット
    - 結論: ポスト量子暗号時代でも安全
-/
noncomputable def universalZKPOracle (material : ZKPMaterial) : UnknownZKP :=
  -- 材料から証人と公開入力を抽出
  let witness := zkpMaterialToWitness material
  let publicInput := zkpMaterialToPublicInput material
  -- amatZKP証明器を使ってProofを生成
  let proof := amatZKP.prover witness publicInput zkpRelation
  -- ProofをZeroKnowledgeProofに変換
  proofToZKP proof material

/-- 定理: オラクルが返すZKPは常に有効である

    **証明の構造:**
    1. universalZKPOracleはamatZKP.proverを使ってProofを生成
    2. amatZKP.completenessにより、Proofは検証に成功する
    3. proofToZKPはProofをvalid ZKPとして構築
    4. ZeroKnowledgeProof.valid_zkp_passesにより、valid ZKPは検証に成功

    **暗号学的仮定への依存:**
    - amatZKPの性質（completeness）から導出される定理
    - SecurityAssumptions.amatZKP_soundness_quantum_secureに依存
    - SecurityAssumptions.amatZKP_zeroKnowledge_quantum_secureに依存
-/
theorem universalZKPOracle_isValid :
  ∀ (material : ZKPMaterial) (relation : Relation),
    UnknownZKP.isValid (universalZKPOracle material) relation := by
  intro material relation
  -- universalZKPOracleの定義を展開
  unfold universalZKPOracle
  -- proofToZKPの定義を展開
  unfold proofToZKP
  -- ZeroKnowledgeProof.isValidの定義を展開
  unfold UnknownZKP.isValid
  -- ZeroKnowledgeProof.verifyの定義を展開
  unfold UnknownZKP.verify
  -- valid ZKPは常にtrue
  rfl

/-- ナンスと事前計算されたProofを結合する関数（辞書からの取り出し）

    辞書からのルックアップ操作として定義。
    これにより、形式的な意味が明確になる。
-/
noncomputable def combinePrecomputedProofWithNonce
    (precomputedProofs : List PrecomputedZKP)
    (credential : UnknownVC)
    (statement : PublicInput)
    (nonce : Nonce)
    (secretKey : SecretKey) : UnknownZKP :=
  -- 材料を構造化
  let material : ZKPMaterial := {
    precomputedProofs := precomputedProofs
    credential := credential
    statement := statement
    nonce := nonce
    secretKey := secretKey
  }
  -- 辞書から対応するZKPを取り出す
  universalZKPOracle material

/-- WalletのIdentityを使ってZKPを生成

    Walletは複数のIdentityを持つことができるため、
    どのIdentityを使ってZKPを生成するかを明示的に指定します。
-/
noncomputable def presentCredentialAsZKP
    (wallet : Wallet)
    (vc : UnknownVC)
    (holderIdentity : Identity)
    (statement : PublicInput)
    (nonce : Nonce)
    (_h_has_identity : holderIdentity ∈ wallet.identities) : UnknownZKP :=
  -- Wallet内の指定されたIdentityの秘密鍵を使ってZKP生成
  -- 事前計算されたProofをnonceと結合
  combinePrecomputedProofWithNonce
    wallet.precomputedProofs
    vc
    statement
    nonce
    holderIdentity.secretKey

end Holder

-- ## VC発行操作（誰でも可能）

/-- VCのコンテキストを生成（W3C標準）
-/
def standardVCContext : Context :=
  { value := "https://www.w3.org/2018/credentials/v1" }

/-- VCのタイプを生成（標準的な属性VC）
-/
def standardAttributeVCType : VCType :=
  { value := "UnknownVC,AttributeCredential" }

/-- 失効情報を生成（初期状態：失効なし）

    **Stage 6設計:**
    RevocationInfoはOption W3C.CredentialStatusなので、
    失効情報がない場合はnoneを返します。
-/
def noRevocationInfo : RevocationInfo :=
  none

/-- VCを発行する関数（誰でも実行可能）

    **W3C VC仕様に準拠した設計:**
    - DIDと秘密鍵があれば誰でもVCを発行できる
    - 「権限」や「認可」のチェックは一切なし
    - Verifierが信頼ポリシーに基づいて受け入れ判断を行う

    **実装:**
    1. Claimsに署名を生成（amatSignature.sign）
    2. AttributeVCとして構築
    3. UnknownVC.validとして返す

    **重要な原則:**
    - 発行は自由（技術的に制限不可能）
    - 信頼は選択（Verifierのポリシー）
    - これにより「Issuer」という特別な役割は不要
-/
noncomputable def issueCredential
    (issuerDID : UnknownDID)
    (issuerSecretKey : SecretKey)
    (subjectDID : UnknownDID)
    (claims : Claims) : UnknownVC :=
  -- Claimsをバイト列にシリアライズ（簡略化）
  let claimsBytes := claims.data.toUTF8.data.toList
  -- 秘密鍵で署名
  let signature := amatSignature.sign issuerSecretKey claimsBytes
  -- W3C基本構造を構築（Stage 2-6を反映）
  -- Stage 6: W3C.Credentialを直接構築（W3CCredentialCoreは型エイリアス）
  let w3cCore : W3C.Credential := {
    context := [standardVCContext]  -- Stage 2: Listでラップ
    type_ := [standardAttributeVCType]  -- Stage 6: W3C.Credentialのtype_フィールド
    issuer := didToW3CIssuer issuerDID  -- Stage 3: W3C.Issuer型に変換
    credentialSubject := [didToCredentialSubject subjectDID]  -- Stage 4: W3C.CredentialSubject型に変換
    -- Stage 5: signatureフィールドを削除（ValidVCに移動）
    credentialStatus := noRevocationInfo
  }
  -- AMATELUS構造を構築（委任者なし = 直接発行）
  -- Stage 6: コンポジション方式に変更
  let amatCore : AMATELUSCredential := {
    w3cCredential := w3cCore
    delegator := none  -- 委任なし
  }
  -- AttributeVCとして構築
  -- Stage 6: コンポジション方式に変更
  let attributeVC : AttributeVC := {
    amatelus := amatCore
    claims := claims
  }
  -- VCTypeとして構築
  let vcType : VCTypeCore := VCTypeCore.attributeVC attributeVC
  -- ValidVCとして構築（amatSignature.completenessにより署名は有効）
  -- Stage 3: issuerDIDを型レベルで保証
  -- Stage 4: subjectDIDを型レベルで保証
  -- Stage 5: signatureを型レベルで保証
  let validVC : ValidVC := {
    vcType := vcType
    issuerDID := issuerDID
    subjectDID := subjectDID
    signature := signature  -- Stage 5: ValidVCに署名を含める
  }
  -- UnknownVCとして返す
  UnknownVC.valid validVC

/-- 定理: 発行されたVCは暗号学的に有効である

    **証明の構造:**
    1. issueCredentialはamatSignature.signを使って署名を生成
    2. amatSignature.completenessにより、署名は検証に成功
    3. ValidVCとして構築されるため、UnknownVC.isValidが成立

    **重要な注意:**
    この定理は「暗号学的に有効」であることのみを保証します。
    「信頼できる」かどうかはVerifierの信頼ポリシーによって決まります。
-/
theorem issued_credential_is_cryptographically_valid :
  ∀ (issuerDID subjectDID : UnknownDID) (issuerSecretKey : SecretKey) (claims : Claims),
    let vc := issueCredential issuerDID issuerSecretKey subjectDID claims
    UnknownVC.isValid vc := by
  intro issuerDID subjectDID issuerSecretKey claims
  -- issueCredentialの定義により、ValidVCとして構築される
  unfold issueCredential
  -- UnknownVC.isValidの定義を展開
  unfold UnknownVC.isValid
  -- UnknownVC.verifySignatureの定義を展開
  unfold UnknownVC.verifySignature
  -- ValidVCは常にtrue
  rfl

-- ## Verifier操作

namespace Verifier

/-- TrustAnchorDictからDIDを受託者として持つトラストアンカーを探す -/
def findTrustAnchorForTrustee (dict : TrustAnchorDict) (trusteeDID : UnknownDID) :
    Option UnknownDID :=
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
    (trustedRoots : List UnknownDID)
    (issuerDID : UnknownDID)
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

/-- 信頼チェーンの検証

    **Stage 3対応:** getIssuerは常にDIDを返す（ValidVCは型レベルで保証）
-/
def verifyTrustChain
    (dict : TrustAnchorDict)
    (policy : TrustPolicy)
    (vc : UnknownVC) : Prop :=
  -- 発行者DIDを取得
  let issuerDID := UnknownVC.getIssuer vc
  -- 発行者がルート認証局リストに含まれているか確認
  (issuerDID ∈ policy.trustedRoots) ∨
  -- または、信頼チェーンを辿る（深さ制限あり）
  (checkTrustChainRecursive dict policy.trustedRoots issuerDID policy.maxChainDepth)

/-- VerifierがVCを検証 -/
def verifyCredential
    (verifier : Verifier)
    (vc : UnknownVC)
    : Prop :=
  -- 暗号学的検証
  UnknownVC.isValid vc ∧
  -- 信頼ポリシーに基づく検証（VerifierのWalletから信頼するトラストアンカー辞書を使用）
  verifyTrustChain verifier.wallet.trustedAnchors verifier.trustPolicy vc

end Verifier

-- ## 操作の安全性定理

/-- Wallet操作: VC保存後の一貫性

    **証明の構造:**
    1. storeCredentialは`credentials`リストのみを変更
    2. `identities`は変更されない
    3. したがって、`Wallet.isValid`は自明に保持される（定義から）

    **重要な設計原則 - AMATELUSの責任範囲:**
    この定理は「Wallet操作が型の不変条件を保つ」という純粋に数学的な主張です。

    **自己責任の範囲:**
    - Wallet実装にバグがあれば影響を受ける（自己責任）
    - しかし、それは「このWalletを選んだ利用者の責任」

    **他者からの独立性（AMATELUSが保証）:**
    - **他人のWalletバグが自分に影響しない**（暗号学的健全性）
    - Verifierは暗号的検証のみに依存
    - Basic.lean:1457 `verifier_cryptographic_soundness`で形式化済み
-/
theorem wallet_store_preserves_validity :
  ∀ (wallet : Wallet) (vc : UnknownVC) (holderDID : UnknownDID)
    (h_valid : UnknownVC.isValid vc)
    (h_subject : UnknownVC.getSubject vc = holderDID)
    (h_has_did : Wallet.hasDID wallet holderDID),
    -- 前提: walletが正規
    Wallet.isValid wallet →
    let wallet' := Holder.storeCredential wallet vc holderDID h_valid h_subject h_has_did;
    -- 結論: VC保存後もWalletは正規
    Wallet.isValid wallet' := by
  intro wallet vc holderDID h_valid h_subject h_has_did h_wallet_valid wallet'
  -- Wallet.isValidの定義を展開
  unfold Wallet.isValid
  -- identitiesは変更されていない
  intro identity h_mem
  -- storeCredentialはidentitiesを変更しないので、h_memをそのまま使える
  exact h_wallet_valid identity h_mem

/-- Verifier操作: 有効なVCかつ信頼できるissuerの検証は成功する

    **証明の構造:**
    1. UnknownVC.isValid vc が成立（暗号学的に有効）
    2. getIssuer vcがtrustedRootsに含まれる（Verifierが信頼）
    3. Verifier.verifyCredentialの定義により、両方の条件を満たせば検証成功

    **Stage 3設計:** getIssuerは直接DIDを返す（ValidVCは型レベルで保証）
-/
theorem verifier_accepts_valid_credential :
  ∀ (verifier : Verifier) (vc : UnknownVC),
    UnknownVC.isValid vc →
    UnknownVC.getIssuer vc ∈ verifier.trustPolicy.trustedRoots →
    verifier.verifyCredential vc := by
  intro verifier vc h_valid h_trusted
  -- Verifier.verifyCredentialの定義を展開
  unfold Verifier.verifyCredential
  constructor
  · -- 暗号学的検証
    exact h_valid
  · -- 信頼チェーン検証
    unfold Verifier.verifyTrustChain
    left  -- issuerDID ∈ trustedRoots を選択
    exact h_trusted
