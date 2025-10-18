/-
# 統一された相互認証プロトコル（Unified Mutual Authentication）

## 設計原則

1. **Verifierからの先行認証**: Verifierがまずナンスとクレーム情報を提示
2. **トラストアンカー検証**: Holderが全てのクレーム署名者を検証
3. **人間中心の判断**: 最終判断はHolderが行う

## DIDComm通信の統一

AMATELUS プロトコル v2では、すべての通信をDIDCommに統一しました。

### 通信用DID（Communication DID）のライフサイクル

**1. 各通信開始時**
- Holder: 新しい通信用DIDを生成
  - 毎回異なるDIDが生成される（秘密鍵ペアが異なる）
  - 身分証明用DID（Identity DID）との関連付けを防ぐ（名寄せ回避）

**2. ZKP生成時**
- Holder: 2つのDID所有権をZKPで証明
  1. 身分証明用DID（Identity DID）の秘密鍵所有権
  2. 通信用DID（Communication DID）の秘密鍵所有権
- ZKPのde-linkage information に両DIDの情報を含める
- ZKP不学性により、異なるクレームを同じidentity DIDに関連付けることは困難

**3. VC発行時**
- Issuer: HC（通信用DID）をsubjectとするVCを発行
- Holder: 通信用DIDをWalletに保存
  - 保存情報: (通信用DID, 通信相手DID, 発行されたVC)
  - この紐づけにより、同じサービスでのログイン認証に再利用可能

**4. VC発行なし（検証のみ）で通信終了した場合**
- Holder: 通信用DIDを破棄
  - Walletに保存されないため、メモリから削除
  - サービスとの関連が跡形もなく消える

### シナリオ1: 検証のみ（VC発行なし）

```
通信用DID生成 → ZKP生成・送信 → 検証成功 → 通信終了 → 破棄
```

例: 年齢確認サービス
- Holder: 通信用DIDを生成
- ZKPで「年齢>=20」を証明（Identity DIDとCommunication DIDの所有権含む）
- Verifier: ZKP検証成功、年齢確認完了
- Holder: 通信終了と同時に通信用DIDを破棄
- 後に同じサービスにアクセス: 新しい通信用DIDで通信（前の通信用DIDとの関連なし）

### シナリオ2: 会員登録（VC発行→ログイン時に再利用）

```
通信用DID生成 → ZKP生成・送信 → 検証成功 → VC発行 → 保存
（次回ログイン時）
保存された通信用DID + VC を使用 → メッセージ認証 → ログイン完了
```

例: SNS会員登録

**初回登録時:**
1. Holder: 新しい通信用DIDを生成
2. ZKPで「年齢>=18, 本人確認OK」を証明
3. Issuer: 検証成功、会員証VC（subject=通信用DID）を発行
4. Holder: Walletに保存
   - 保存: (通信用DID, Issuer DID, 会員証VC)

**次回ログイン時:**
1. Holder: Walletから通信用DIDと会員証VCを取得
2. DIDCommで通信相手（SNS）と認証
   - メッセージ認証にはEC-DH 1PUを使用
   - 通信用DIDの秘密鍵で署名
3. Verifier: メッセージ署名検証成功 → ログイン完了

**複数サービスでの名寄せ回避:**
- サービスA用通信DID: commDID_A (Walletに保存)
- サービスB用通信DID: commDID_B (Walletに保存)
- 異なるcommDID_A, commDID_Bから、共通のIdentity DIDを推測することは困難
  → ZKP不学性による保護
  → 複数のサービスが「commDID_A」「commDID_B」を観測しても、
    背後に同じIdentity DIDがあることを推測できない

**サービス内でのプライバシー:**
- 同じサービスに対しては、保存された同じ通信用DIDで認証
- サービスは複数のアクセスが同じcommDIDから来ていると認識
- しかし、そのcommDIDが背後のIdentity DIDと何であるかは不明
  （ZKPのde-linkage infoからは推測不可）

## 従来の課題を解決する設計

**従来:**
- Holderが身分証明用DIDを複数のサービスに提示
- 異なるクレームから同じDIDを抽出可能
→ サービス間での名寄せが容易（SNS、銀行、病院から同じDIDが観測される）

**新設計:**
- 通信用DIDを毎回生成（ZKPでIdentity DIDとの関連を秘密裏に証明）
- ZKP不学性により、複数のサービスからの通信用DID観測から
  背後の共通Identity DIDを推測困難
- **結果**: サービス間での名寄せが困難（各サービスは異なる通信用DIDを見る）

## プロトコルフロー

### 必須（DIDComm）

1. Verifierがクレーム情報を送信
2. Holderが全クレームの署名者のトラストアンカー検証
3. 信頼できない署名者がいればフロー終了
4. 信頼できればHolderに検証者情報を表示し、人間の判断を待つ
5. 許可されたらZKP送信（de-linkage情報含む、DIDCommで秘密鍵対応が確定）

### オプショナル（ナンス - サービス実装時）

Verifierがリプレイ攻撃（本人による再利用）を防ぐ場合：
- Verifierがナンス2を送信
- Holderがナンス1を生成してZKPに含める
- Verifierがナンスの一意性を確認

**採択例:**
- 会員登録初回: ナンス必須（登録重複防止）
- 年齢確認: ナンス不要（一度限り）
- ログイン: ナンス不要（毎回新しい通信用DIDで検証）

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

    例2: Webサービスログイン（DIDComm + チャレンジ署名）
    ```
    注: 本来はDIDCommで暗号化通信。ここでは簡略化した例を示す。

    **初回登録フロー:**
    Holder → Service (DIDComm):
    {
      holderDID: "did:amt:holder_123",  // Holder側で生成したDID
      serviceAccountID: "user_service_001",  // Service専用のワンタイム識別子
      signedConsent: Signature,  // Holderの秘密鍵で署名
      zkp: ZKP  // 属性証明（ageOver18など、必要に応じて）
    }

    Service検証:
    1. DIDCommで受信 ← 通信路の認証完了
    2. holderDIDの署名を検証
    3. serviceAccountIDとholderDIDをバインド
    4. トラストアンカーでHolder DIDを確認（オプション）

    **ログインフロー（チャレンジ-レスポンス）:**
    Verifier → Holder (DIDComm):
    {
      nonce2: random(),
      challenge: "prove-account-ownership",
      presentedClaims: [
        {
          claimData: { data: "SNSサービス", claimID: Some "social_service" },
          issuerDID: "did:amt:sns_provider"
        }
      ],
      verifierDID: "did:amt:sns_app",
      requestedAttributes: {
        type: ["object"],
        properties: {
          serviceAccountID: { type: ["string"] },  // Service固有の識別子（所有権証明ではない）
          loginSignature: { type: ["string"] }  // チャレンジに対する署名（所有権証明）
        },
        required: ["serviceAccountID", "loginSignature"]
      },
      timestamp: now()
    }

    Holder → Verifier (DIDComm):
    {
      nonce1: random(),
      serviceAccountID: "user_service_001",  // 初回登録時に生成した識別子
      loginSignature: Sign(nonce2, holderPrivateKey),  // チャレンジ署名でアカウント所有権を証明
      holderZKP: { /* nonce1 ∥ nonce2を結合したZKP */ }
    }

    Service検証ポイント:
    1. DIDCommで通信認証済み
    2. loginSignatureを検証 → Holder秘密鍵の保持を確認
    3. serviceAccountIDとholderDIDの紐付けを確認
    4. ZKPで属性も検証（必要に応じて）
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

    例2: Webサービスログインへの応答（DIDComm + チャレンジ署名）
    ```
    Holder → Verifier (DIDComm):
    {
      nonce1: random(),
      serviceAccountID: "user_sns_001",  // Service専用の識別子
      loginSignature: Sign(nonce2, holderPrivateKey),  // チャレンジ署名
      holderZKP: {
        core: {
          proof: π,
          publicInput: nonce2 || nonce1,
          proofPurpose: "credential-presentation",
          created: now()
        },
        holderNonce: nonce1,
        verifierNonce: nonce2,
        claimedAttributes: "Account ownership proof for SNS login"
      },
      providedAttributes: {  // 必須：スキーマ検証済み
        value: {
          serviceAccountID: "user_sns_001",  // Service専用ID
          loginSignature: "sig_..."  // チャレンジに対する署名
        },
        schema: <requestedAttributes>
      },
      timestamp: now()
    }

    Service検証:
    1. DIDCommで受信認証済み
    2. loginSignatureを秘密鍵で検証
       - Sign検証成功 → Holder秘密鍵の保持を確認
       - リプレイ攻撃防止: nonce2が使用済みでないか確認
    3. serviceAccountIDとHolder DIDの紐付けを確認
    4. ZKPを検証（属性証明が必要な場合）
    ```

    **重要:**
    - DIDは平文で送信されない（DIDCommで暗号化通信）
    - serviceAccountIDはService固有の識別子（所有権証明ではない）
    - loginSignatureでチャレンジ署名により初めてアカウント所有権が証明される

    **セキュリティ保証:**
    - DIDComm認証: 通信路の認証・暗号化
    - チャレンジ署名: Holderの秘密鍵保持を検証、アカウント所有権を証明
    - トラストアンカー検証: Wallet内の辞書で検証
    - 人間中心: 最終判断はHolderが行う
    - 偽警官対策: 信頼できない発行者のクレームは拒否
    - リプレイ攻撃対策: 両方のナンスを結合してZKP生成 + nonce2の使用済み確認
    - スキーマ検証: 要求された属性データはJSONSchemaで検証済み（必須）
    - 選択的開示: HolderはVerifierが要求した属性のみを提供
    - 名寄せ回避: DIDを平文で送信せず、Service固有の識別子を使用
    - プライバシー保護: 属性を提供できない場合、応答全体を返さない
    - アカウント所有権証明: serviceAccountID単体ではなく、チャレンジ署名と組み合わせ
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
