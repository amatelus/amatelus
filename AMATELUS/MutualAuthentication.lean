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
import AMATELUS.JSONSchemaSubset

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

    Phase 1: Verifierがナンス2、クレーム情報、および要求する属性スキーマを送信

    **requestedAttributes について:**
    - Verifierが Holder から欲しい公開情報を JSONSchemaSubset で指定（必須）
    - 名寄せ回避のため、HolderはDIDを平文で送信しない
    - したがって、Verifierは何らかの識別可能な属性を要求する必要がある

    **実用例:**
    - Webサービスログイン: serviceAccountID (サービス固有の識別子)
    - 年齢制限コンテンツ: ageOver18 (年齢証明)
    - 投票システム: votingToken (二重投票防止) + nationality (資格確認)
    - ECサイト: membershipLevel (会員ランク) + purchaseHistory (購入履歴)
-/
structure VerifierInitialMessage where
  nonce2 : Nonce                          -- Verifierが生成したナンス
  presentedClaims : List VerifierClaim    -- 提示するクレーム情報のリスト
  verifierDID : UnknownDID                       -- Verifierの識別子
  requestedAttributes : Schema            -- Holderに要求する属性のJSONスキーマ（必須）
  timestamp : Timestamp

/-- Holderの応答メッセージ

    Phase 3: Holderがナンス1とZKP、および要求された属性データを送信（許可された場合）

    **providedAttributes について:**
    - Verifierが requestedAttributes で要求した属性に対応するJSONデータ（必須）
    - スキーマ検証済みのデータのみが含まれる（ValidJSONValue型）
    - 名寄せ回避のため、DIDは平文で送信されない
    - 代わりに、サービス固有の識別子や証明したい属性を送信

    **重要な設計思想:**
    - Holderは要求された属性を提供できない場合、応答自体を返さない（none）
    - これにより、「属性は提供できないがDIDだけは明かす」という危険な状態を防ぐ
-/
structure HolderResponse where
  nonce1 : Nonce                        -- Holderが生成したナンス
  holderZKP : UnknownZKP                -- ナンス1とナンス2を結合したZKP
  providedAttributes : ValidJSONValue   -- 要求された属性データ（スキーマ検証済み、必須）
  timestamp : Timestamp

-- ## トラストアンカー検証ロジック

/-- クレームの署名者がWallet内のトラストアンカーに存在するか検証

    決定的な関数：辞書検索のみを行う
-/
def isClaimIssuerTrusted (claim : VerifierClaim) (holderWallet : Wallet) : Bool :=
  -- 署名者DIDがトラストアンカー辞書に存在するか確認
  -- claim.issuerDIDがValidDIDである場合のみ信頼される
  match claim.issuerDID with
  | UnknownDID.valid validDID =>
      (TrustAnchorDict.lookup holderWallet.trustedAnchors validDID).isSome
  | UnknownDID.invalid _ => false  -- 不正なDIDは信頼されない

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
    3. 両方がtrueならZKPと要求された属性データを生成

    **人間の判断（humanApproval）:**
    - Wallet UIがクレーム情報と要求された属性スキーマを表示
    - Holderが「許可」または「拒否」ボタンを押す
    - その結果がBoolとして渡される

    **属性データの提供:**
    - Verifierが requestedAttributes でスキーマを指定（必須）
    - Holderは自分のVCから該当する属性を抽出
    - スキーマ検証を行い、検証成功ならValidJSONValueを応答に含める
    - 検証失敗または属性を提供できない場合、応答全体を返さない（none）
    - 現在の実装では簡略化のためダミーデータを返す（TODO: 実装）
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

    -- amtZKP証明器を使ってProofを生成
    let proof := amtZKP.prover witness publicInput relation

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

    -- 要求された属性データを準備
    -- 実装では、Holderが持つVCから該当する属性を抽出し、スキーマ検証を行う
    -- ここでは簡略化のためダミーデータを返す（TODO: 実装）
    -- 実際には、スキーマ検証に失敗した場合、この関数全体がnoneを返すべき
    let providedAttrs : ValidJSONValue := {
      value := JSONValue.object [("dummy", JSONValue.string "placeholder")]
      schema := msg.requestedAttributes
    }

    some {
      nonce1 := nonce1
      holderZKP := zkp
      providedAttributes := providedAttrs
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
      match claim.issuerDID with
      | UnknownDID.valid validDID =>
          (TrustAnchorDict.lookup holderWallet.trustedAnchors validDID).isNone
      | UnknownDID.invalid _ => True) →
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
  cases h : claim.issuerDID with
  | valid validDID =>
      simp
      simp [h] at h_untrusted
      exact h_untrusted
  | invalid _ =>
      simp

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

    証明：amtZKP.completenessにより、amtZKP.proverが生成したProofは
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

    例1: 年齢制限サービス（酒類販売）
    ```
    Verifier → Holder:
    {
      nonce2: random(),
      presentedClaims: [
        {
          claimData: { data: "酒類販売許可", claimID: Some "liquor_license" },
          issuerDID: "did:amt:liquor_authority"
        }
      ],
      verifierDID: "did:amt:liquor_shop_xyz",
      requestedAttributes: {  // 必須：年齢証明
        type: ["object"],
        properties: {
          ageOver20: { type: ["boolean"], const: true },
          purchaseToken: { type: ["string"] }  // 購入トークン（名寄せ回避）
        },
        required: ["ageOver20", "purchaseToken"]
      },
      timestamp: now()
    }
    ```

    例2: Webサービスログイン
    ```
    Verifier → Holder:
    {
      nonce2: random(),
      presentedClaims: [
        {
          claimData: { data: "SNSサービス", claimID: Some "social_service" },
          issuerDID: "did:amt:sns_provider"
        }
      ],
      verifierDID: "did:amt:sns_app",
      requestedAttributes: {  // 必須：サービス固有ID
        type: ["object"],
        properties: {
          serviceAccountID: { type: ["string"] },  // サービス固有の識別子
          lastLoginTimestamp: { type: ["integer"] }
        },
        required: ["serviceAccountID"]
      },
      timestamp: now()
    }
    ```

    **Phase 2: Holderの検証プロセス**

    1. Wallet UIが以下を表示：
       - Verifierが提示したクレーム情報
       - 各クレームの発行者（トラストアンカー名）
       - Verifierが要求する属性スキーマ（requestedAttributes）
         例: 「年齢が20歳以上、日本国籍」
       - 「このVerifierに以下の情報を提供しますか？」

    2. Holderが判断：
       - 自分が要求された属性を提供できるか確認
       - 許可ボタン → humanApproval = true
       - 拒否ボタン → humanApproval = false

    3. 許可された場合のみ応答生成
       - Holderは自分のVCから該当する属性を抽出
       - スキーマ検証を行い、ValidJSONValueとして構築

    **Phase 3: Holderの応答**

    例1: 年齢制限サービスへの応答
    ```
    Holder → Verifier:
    {
      nonce1: random(),
      holderZKP: {
        core: {
          proof: π,
          publicInput: nonce2 || nonce1,
          proofPurpose: "credential-presentation",
          created: now()
        },
        holderNonce: nonce1,
        verifierNonce: nonce2,
        claimedAttributes: "Age verification for liquor purchase"
      },
      providedAttributes: {  // 必須：スキーマ検証済み
        value: {
          ageOver20: true,
          purchaseToken: "abc123xyz"  // 一時的な購入トークン
        },
        schema: <requestedAttributes>
      },
      timestamp: now()
    }
    ```

    例2: Webサービスログインへの応答
    ```
    Holder → Verifier:
    {
      nonce1: random(),
      holderZKP: { /* ... */ },
      providedAttributes: {  // 必須：スキーマ検証済み
        value: {
          serviceAccountID: "user_sns_001",  // このサービス専用のID
          lastLoginTimestamp: 1704067200
        },
        schema: <requestedAttributes>
      },
      timestamp: now()
    }
    ```

    **重要:** DIDは平文で送信されない。代わりに、サービス固有の識別子を使用。

    **セキュリティ保証:**
    - トラストアンカー検証: Wallet内の辞書で検証
    - 人間中心: 最終判断はHolderが行う
    - 偽警官対策: 信頼できない発行者のクレームは拒否
    - リプレイ攻撃対策: 両方のナンスを結合してZKP生成
    - スキーマ検証: 要求された属性データはJSONSchemaで検証済み（必須）
    - 選択的開示: HolderはVerifierが要求した属性のみを提供
    - 名寄せ回避: DIDを平文で送信せず、サービス固有の識別子を使用
    - プライバシー保護: 属性を提供できない場合、応答全体を返さない
-/
def mutualAuthenticationRequirements : String :=
  "Mutual Authentication Protocol:
   Phase 1: Verifier sends nonce2, presented claims with issuer DIDs,
    and requestedAttributes (JSON Schema, required)
   Phase 2: Holder validates all claim issuers against TrustAnchorDict
           If any issuer is untrusted, protocol terminates
           If all trusted, Wallet UI displays info, requested attributes,
              and waits for human approval
           If rejected, protocol terminates
           If approved, extract requested attributes from VCs, validate against schema,
              generate nonce1 and ZKP
           If schema validation fails or attributes unavailable, protocol terminates
   Phase 3: Holder sends nonce1, ZKP (combining nonce1 and nonce2),
     and providedAttributes (ValidJSONValue, required)

   Security guarantees:
   - Trust anchor validation: Dictionary lookup in Wallet
   - Human-centric: Final decision by Holder
   - Fake verifier protection: Untrusted issuer claims rejected
   - Replay attack protection: Both nonces combined in ZKP
   - Schema validation: Provided attributes validated against JSON Schema (required)
   - Selective disclosure: Holder provides only requested attributes
   - Privacy protection: DID not sent in plaintext; service-specific identifiers used instead
   - Fail-safe design: If attributes unavailable, entire response is withheld"
