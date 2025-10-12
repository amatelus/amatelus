/-
# 統一された相互認証プロトコル（Unified Mutual Authentication）

## 設計原則

1. **Verifierからの先行認証**: Verifierがまずナンスとクレーム情報を提示
2. **トラストアンカー検証**: Holderが全てのクレーム署名者を検証
3. **人間中心の判断**: 最終判断はHolderが行う

## プロトコルフロー

1. Verifierがナンス2とZKP（クレーム情報含む）を送信
2. Holderが全クレームの署名者のトラストアンカー検証
3. 信頼できない署名者がいればフロー終了
4. 信頼できればHolderに検証者情報を表示し、人間の判断を待つ
5. 許可されたらナンス1を生成してZKP送信

-/

import AMATELUS.DID
import AMATELUS.VC
import AMATELUS.ZKP
import AMATELUS.Roles
import AMATELUS.SecurityAssumptions
import AMATELUS.Cryptographic
import AMATELUS.Operations

-- ## プロトコルメッセージ構造

/-- Verifierが提示するクレーム情報

    Verifierは自身が持つVCから、Holderに信頼してもらえそうな
    情報を任意に含めることができる。

    各クレームには、そのクレームを署名した発行者のDIDを含める。
    自己署名でもよいが、それを受け入れるかはHolder次第。
-/
structure VerifierClaim where
  claimData : Claims           -- クレームの内容
  issuerDID : UnknownDID              -- このクレームを署名した発行者のDID
  deriving Repr, DecidableEq

/-- Verifierの初期メッセージ

    Phase 1: Verifierがナンス2とクレーム情報を送信
-/
structure VerifierInitialMessage where
  nonce2 : Nonce                          -- Verifierが生成したナンス
  presentedClaims : List VerifierClaim    -- 提示するクレーム情報のリスト
  verifierDID : UnknownDID                       -- Verifierの識別子
  timestamp : Timestamp
  deriving Repr

/-- Holderの応答メッセージ

    Phase 3: Holderがナンス1とZKPを送信（許可された場合）
-/
structure HolderResponse where
  nonce1 : Nonce                -- Holderが生成したナンス
  holderZKP : UnknownZKP  -- ナンス1とナンス2を結合したZKP
  timestamp : Timestamp

-- ## トラストアンカー検証ロジック

/-- クレームの署名者がWallet内のトラストアンカーに存在するか検証

    決定的な関数：辞書検索のみを行う
-/
def isClaimIssuerTrusted (claim : VerifierClaim) (holderWallet : Wallet) : Bool :=
  -- 署名者DIDがトラストアンカー辞書に存在するか確認
  (TrustAnchorDict.lookup holderWallet.trustedAnchors claim.issuerDID).isSome

/-- 全てのクレームが信頼できる発行者によるものか検証

    決定的な関数：リストの全要素に対して検証を行う
-/
def validateAllClaimIssuers (claims : List VerifierClaim) (holderWallet : Wallet) : Bool :=
  claims.all (fun claim => isClaimIssuerTrusted claim holderWallet)

/-- Verifierメッセージの基本検証

    決定的な関数：
    1. クレームリストが空でないこと
    2. 全てのクレーム発行者が信頼できること
-/
def validateVerifierMessage (msg : VerifierInitialMessage) (holderWallet : Wallet) : Bool :=
  -- クレームが少なくとも1つ存在する
  (!msg.presentedClaims.isEmpty) &&
  -- 全てのクレーム発行者が信頼できる
  validateAllClaimIssuers msg.presentedClaims holderWallet

-- ## Holderの判断と応答

/-- Holderの応答生成（人間の判断を外部入力として受け取る）

    この関数は以下の決定的なステップで構成される：
    1. Verifierメッセージの基本検証（決定的）
    2. 人間の判断を外部入力として受け取る（パラメータ）
    3. 両方がtrueならZKPを生成（amatZKP.proverを使用）

    **人間の判断（humanApproval）:**
    - Wallet UIがクレーム情報を表示
    - Holderが「許可」または「拒否」ボタンを押す
    - その結果がBoolとして渡される
-/
noncomputable def holderRespond
    (msg : VerifierInitialMessage)
    (holderWallet : Wallet)
    (holderIdentity : Identity)
    (humanApproval : Bool) -- 人間の判断（外部入力）
    (_h_has_identity : holderIdentity ∈ holderWallet.identities)
    : Option HolderResponse :=
  -- 基本検証
  if validateVerifierMessage msg holderWallet && humanApproval then
    -- ナンス1を生成（実装では暗号学的ランダム）
    let nonce1 : Nonce := ⟨[]⟩  -- プレースホルダ

    -- 公開入力を構築：両方のナンスを含める
    let publicInput : PublicInput := {
      data := msg.nonce2.value ++ nonce1.value
    }

    -- 証人を構築：Holderの秘密鍵
    let witness : Witness := Witness.mk holderIdentity.secretKey.bytes

    -- 関係式（実装依存）
    let relation : Relation := fun _ _ => true

    -- amatZKP証明器を使ってProofを生成
    let proof := amatZKP.prover witness publicInput relation

    -- ProofをZeroKnowledgeProofに変換
    let holderZKPCore : HolderCredentialZKPCore := {
      core := {
        proof := proof
        publicInput := publicInput
        proofPurpose := "credential-presentation"
        created := { unixTime := 0 }  -- プレースホルダ
      }
      holderNonce := nonce1  -- Holderが生成したナンス
      verifierNonce := msg.nonce2  -- Verifierが生成したナンス
      claimedAttributes := "Identity verification"
    }

    let zkp := UnknownZKP.valid {
      zkpType := Sum.inr holderZKPCore
    }

    some {
      nonce1 := nonce1
      holderZKP := zkp
      timestamp := { unixTime := 0 }  -- プレースホルダ
    }
  else
    none  -- 検証失敗または拒否 → フロー終了

-- ## セキュリティ定理

/-- Theorem: 信頼できない発行者のクレームを含むメッセージは拒否される

    証明：validateVerifierMessage関数の定義により自明
-/
theorem untrusted_issuer_rejected :
  ∀ (msg : VerifierInitialMessage) (holderWallet : Wallet),
    -- 信頼できない発行者が存在する場合
    (∃ claim ∈ msg.presentedClaims,
      (TrustAnchorDict.lookup holderWallet.trustedAnchors claim.issuerDID).isNone) →
    -- 検証失敗
    validateVerifierMessage msg holderWallet = false := by
  intro msg holderWallet ⟨claim, h_mem, h_untrusted⟩
  unfold validateVerifierMessage
  simp
  intro _  -- ¬msg.presentedClaims = [] を仮定として導入
  unfold validateAllClaimIssuers
  simp
  -- 信頼できないクレームが存在することを示す
  refine ⟨claim, h_mem, ?_⟩
  unfold isClaimIssuerTrusted
  simp at h_untrusted ⊢
  rw [h_untrusted]

/-- Theorem: 人間が拒否した場合、応答は生成されない

    証明：holderRespond関数の定義により自明
-/
theorem human_rejection_stops_protocol :
  ∀ (msg : VerifierInitialMessage) (holderWallet : Wallet)
    (holderIdentity : Identity) (h_has_identity : holderIdentity ∈ holderWallet.identities),
    -- 基本検証が成功しても、人間が拒否した場合
    validateVerifierMessage msg holderWallet = true →
    -- 応答は生成されない
    holderRespond msg holderWallet holderIdentity false h_has_identity = none := by
  intro msg holderWallet holderIdentity h_has_identity h_valid
  unfold holderRespond
  rw [h_valid]
  simp

/-- Theorem: 信頼できる発行者のみで、人間が許可した場合、応答が生成される

    証明：holderRespond関数の定義により自明
-/
theorem trusted_and_approved_generates_response :
  ∀ (msg : VerifierInitialMessage) (holderWallet : Wallet)
    (holderIdentity : Identity) (h_has_identity : holderIdentity ∈ holderWallet.identities),
    -- 基本検証が成功し、人間が許可した場合
    validateVerifierMessage msg holderWallet = true →
    -- 応答が生成される
    (holderRespond msg holderWallet holderIdentity true h_has_identity).isSome := by
  intro msg holderWallet holderIdentity h_has_identity h_valid
  unfold holderRespond
  rw [h_valid]
  simp

/-- Theorem: 生成されたZKPは有効である

    証明：amatZKP.completenessにより、amatZKP.proverが生成したProofは
    検証に成功することが保証される
-/
theorem generated_zkp_is_valid :
  ∀ (msg : VerifierInitialMessage) (holderWallet : Wallet)
    (holderIdentity : Identity) (h_has_identity : holderIdentity ∈ holderWallet.identities)
    (response : HolderResponse),
    -- 応答が生成された場合
    holderRespond msg holderWallet holderIdentity true h_has_identity = some response →
    -- ZKPは有効である
    ∃ (relation : Relation), UnknownZKP.isValid response.holderZKP relation := by
  intro msg holderWallet holderIdentity h_has_identity response h_response
  -- holderRespondの定義を展開すると、responseのholderZKPはZeroKnowledgeProof.validとして構築される
  -- したがって、任意のrelationに対してisValidが成立
  refine ⟨(fun _ _ => true), ?_⟩
  -- holderRespondの定義により、holderZKPはZeroKnowledgeProof.validとして構築されている
  -- ZeroKnowledgeProof.validはZeroKnowledgeProof.verifyでtrueを返す
  unfold UnknownZKP.isValid UnknownZKP.verify
  -- holderRespondの定義から、responseのholderZKPはvalidコンストラクタで構築されている
  -- ので、verify (valid _) _ = trueが成立
  unfold holderRespond at h_response
  -- 条件分岐を処理
  by_cases h : validateVerifierMessage msg holderWallet && true
  · -- 条件が成立する場合
    simp only [h, ite_true] at h_response
    -- h_responseは some {...} = some response の形
    simp only [Option.some.injEq] at h_response
    -- responseの定義を使う
    rw [← h_response]
    -- holderZKPはZeroKnowledgeProof.validとして構築されているので、verifyはtrueを返す
  · -- 条件が不成立の場合（矛盾）
    simp only [h, ite_false] at h_response
    -- none = some response は矛盾
    contradiction

-- ## プロトコル統合

/-- 相互認証セッション（簡略版）

    Phase 1: Verifierがメッセージを送信
    Phase 2: Holderが検証して応答（または拒否）
-/
structure MutualAuthSession where
  verifierMessage : VerifierInitialMessage
  holderResponse : Option HolderResponse

/-- セッション実行関数 -/
noncomputable def executeMutualAuth
    (verifierMessage : VerifierInitialMessage)
    (holderWallet : Wallet)
    (holderIdentity : Identity)
    (humanApproval : Bool)
    (h_has_identity : holderIdentity ∈ holderWallet.identities)
    : MutualAuthSession :=
  {
    verifierMessage := verifierMessage
    holderResponse :=
      holderRespond verifierMessage holderWallet holderIdentity humanApproval h_has_identity
  }

-- ## 実装要件

/-- 実装要件: 相互認証プロトコル

    **Phase 1: Verifierの初期メッセージ**
    ```
    Verifier → Holder:
    {
      nonce2: random(),  // 必須：暗号学的ランダムナンス
      presentedClaims: [
        {
          claimData: { data: "警察官資格", claimID: Some "police_officer" },
          issuerDID: "did:amatelus:police_hq"  // 警察庁のDID
        },
        {
          claimData: { data: "管轄区域：東京都", claimID: Some "jurisdiction" },
          issuerDID: "did:amatelus:police_hq"  // 警察庁のDID（自己署名可）
        }
      ],
      verifierDID: "did:amatelus:officer123",
      timestamp: now()
    }
    ```

    **Phase 2: Holderの検証プロセス**

    1. Wallet UIが以下を表示：
       - Verifierが提示したクレーム情報
       - 各クレームの発行者（トラストアンカー名）
       - 「このVerifierに情報を提供しますか？」

    2. Holderが判断：
       - 許可ボタン → humanApproval = true
       - 拒否ボタン → humanApproval = false

    3. 許可された場合のみ応答生成

    **Phase 3: Holderの応答**
    ```
    Holder → Verifier:
    {
      nonce1: random(),  // Holderが生成したナンス
      holderZKP: {
        core: {
          proof: π,
          publicInput: nonce2 || nonce1,  // 両方のナンスを結合
          proofPurpose: "credential-presentation",
          created: now()
        },
        holderNonce: nonce1,
        verifierNonce: nonce2,
        claimedAttributes: "Identity verification"
      },
      timestamp: now()
    }
    ```

    **セキュリティ保証:**
    - トラストアンカー検証: Wallet内の辞書で検証
    - 人間中心: 最終判断はHolderが行う
    - 偽警官対策: 信頼できない発行者のクレームは拒否
    - リプレイ攻撃対策: 両方のナンスを結合してZKP生成
-/
def mutualAuthenticationRequirements : String :=
  "Mutual Authentication Protocol:
   Phase 1: Verifier sends nonce2 and presented claims with issuer DIDs
   Phase 2: Holder validates all claim issuers against TrustAnchorDict
           If any issuer is untrusted, protocol terminates
           If all trusted, Wallet UI displays info and waits for human approval
           If rejected, protocol terminates
           If approved, generate nonce1 and ZKP
   Phase 3: Holder sends nonce1 and ZKP (combining nonce1 and nonce2)

   Security guarantees:
   - Trust anchor validation: Dictionary lookup in Wallet
   - Human-centric: Final decision by Holder
   - Fake verifier protection: Untrusted issuer claims rejected
   - Replay attack protection: Both nonces combined in ZKP"
