/-
# 通信レイヤー定義

このファイルは、AMATELUSプロトコルの通信レイヤーを定義します。

**設計思想（信頼境界）:**
- 送信側: Validなデータを送信
- 通信レイヤー: シリアライズ → 送信（HTTPS/BLE/DIDComm） → 受信 → デシリアライズ
- 受信側: Unknownなデータとして受け取り、必ず検証

**2つの通信方式:**

1. **ZKP over HTTPS/BLE**: ZKP専用の軽量プロトコル
   - ValidZKP → UnknownZKP の送信のみ
   - 受信側で必ず暗号的検証が必要

2. **DIDComm v2.1 + did:amt仕様**: DIDベースの相互認証通信プロトコル
   - メッセージにはDID文字列が含まれる
   - **did:amt特有の制約**: DID文字列だけからDIDDocumentを解決できない
   - そのため、Holderが明示的にDIDDocumentを送信する（Optional）
   - ECDH-1PU認証付き暗号化により中間者攻撃を防ぐ
   - 送信: ValidDID + Optional(ValidDIDDocument) + Optional(VC/ZKP)
   - 受信: UnknownDID + Optional(UnknownDIDDocument) + Optional(UnknownVC/UnknownZKP)
   - すべてのデータが受信側でUnknownとして扱われる

この設計により、型システムで受信側の検証忘れを防ぐことができる。
-/

import AMATELUS.DID
import AMATELUS.VC
import AMATELUS.ZKP

-- ## 通信チャネルの定義

/-- 通信チャネルの種類

    **設計思想:**
    AMATELUSでは2つの異なる通信方式を使用します：

    1. **ZKPoverHTTPSorBLE**: ZKP専用の軽量な通信プロトコル
       - ValidZKP → UnknownZKP の送信のみ
       - 受信側で必ず暗号的検証が必要

    2. **DIDComm**: DIDベースの相互認証通信プロトコル（did:amt仕様に準拠）
       - 送信: ValidDID + Optional(ValidDIDDocument/VC/ZKP)
       - 受信: UnknownDID + Optional(UnknownDIDDocument/VC/ZKP)
       - **did:amt制約**: DID解決ができないため、Holderが明示的にDIDDocumentを送信
       - すべてのデータが受信側でUnknownとして扱われ、検証が必要
-/
inductive Channel
  | ZKPoverHTTPSorBLE     -- ZKP over HTTPS or Bluetooth Low Energy
  | DIDComm   -- Decentralized Identifier Communication
  deriving Repr, DecidableEq

-- ## DIDCommメッセージ構造

/-- DIDCommメッセージ（送信側）

    **構造:**
    - senderDID: 送信者のValidDID（メッセージの`from`フィールド）
    - senderDoc: オプショナルなValidDIDDocument（did:amt仕様に準拠）
    - vcs: ValidVCのリスト（IssuerがHolderに発行する場合、Verifierが認証情報を送る場合など）
    - zkp: オプショナルなValidZKP（相互認証時など）

    **設計思想（DIDComm v2.1 + did:amt仕様に準拠）:**
    - メッセージにはDID文字列のみが含まれる
    - **did:amt特有の制約**: DID文字列だけからDIDDocumentを解決できない
    - そのため、Holderが明示的にDIDDocumentを送信する必要がある（Optional）
    - 暗号化にはECDH-1PUを使用（送信者のSK + 受信者のPKで認証付き暗号化）

    **複数VC対応:**
    - Verifier認証メッセージなど、複数のVCを送信する必要がある場合に対応
    - 単一VCの場合は、リストに1つだけ含める

    **did:amt仕様（Section 1.2.2 Read）:**
    > The resolution of a `did:amt` is completed locally by a verifier who receives
    > the `[AMT Version Number, Public Key]` pair from the owner and executes the
    > same steps from 1.2.1, step 3 onwards.

    つまり、HolderがVerifierに`[AMT Version Number, Public Key]`ペア
    （実質的にDIDDocument）を送信しない限り、VerifierはDIDを検証できない。
-/
structure DIDCommMessageSend where
  senderDID : ValidDID
  senderDoc : Option ValidDIDDocument
  vcs : List ValidVC
  zkp : Option ValidZKP

/-- DIDCommメッセージ（受信側）

    **構造:**
    - senderDID: 送信者のUnknownDID（メッセージから取得、未検証）
    - senderDoc: 送信者のオプショナルなUnknownDIDDocument（メッセージから取得、未検証）
    - vcs: UnknownVCのリスト（受信側で検証が必要）
    - zkp: オプショナルなUnknownZKP（受信側で暗号的検証が必要）

    **設計思想（信頼境界）:**
    - DID: メッセージから取得するが、未検証（UnknownDID）
    - DIDDocument: メッセージから取得するが、所有権未検証（Option UnknownDIDDocument）
    - VC/ZKP: 受信側はこれを信頼できないため、Unknownとして扱う

    **複数VC対応:**
    - Verifier認証メッセージなど、複数のVCを受信する必要がある場合に対応
    - すべてのVCはUnknownとして扱われ、個別に検証が必要

    **実際のDIDComm + did:amt動作:**
    1. メッセージを受信（DID文字列 + オプショナルなDIDDocumentを取得）
    2. **did:amt制約**: DID文字列だけからは解決できないため、送信側がDIDDocumentを含める必要がある
    3. 受信したDIDDocumentから公開鍵を取得してメッセージを復号化
    4. DIDとDIDDocumentの整合性検証（`UnknownDID.isValid`）
    5. VC、ZKPをそれぞれ検証

    **理由（すべてUnknown）:**
    1. 通信経路での改ざんの可能性（中間者攻撃）
    2. 送信側のバグによる不正なシリアライズ
    3. ネットワークエラーによるデータ破損
    4. 受信側のバグによる不正なデシリアライズ
    5. 送信側が不正なDIDDocumentを送信する可能性
-/
structure DIDCommMessageReceive where
  senderDID : UnknownDID
  senderDoc : Option UnknownDIDDocument
  vcs : List UnknownVC
  zkp : Option UnknownZKP

-- ## ZKP over HTTPS/BLE 通信関数

namespace Network

/-- ZKP送信（ZKP over HTTPS/BLE）: ValidZKPを送信し、UnknownZKPとして受信される

    **設計思想:**
    HolderがVerifierにZKPを送信する際、Holder側ではValidZKP（暗号的に正しい）
    だが、Verifier側はこれを信頼できないため、Unknownとして受け取る。

    **型システムによる保証:**
    受信側は必ず`UnknownZKP.verify`で暗号的検証を行う必要がある。
    検証せずに使用することは型エラーになる。

    **実装:**
    この関数は通信プロセス（シリアライズ → 送信（HTTPS/BLE） → 受信 → デシリアライズ）を
    抽象化したもの。実際の通信エラーや改ざんは、この関数の外でモデル化される
    （例: 攻撃者が`UnknownZKP.invalid`を注入）。
-/
noncomputable def sendZKPoverHTTPSorBLE (zkp : ValidZKP) : UnknownZKP :=
  -- 理想的なケース: 送信側が正しくValidZKPを送り、改ざんされずに届く
  -- しかし、受信側はこれを信頼できないため、Unknownとして扱う
  UnknownZKP.valid zkp

/-- ZKP受信（ZKP over HTTPS/BLE）: UnknownZKPを検証してValidZKPに変換

    **使用例:**
    ```lean
    -- 送信側（Holder）
    let zkp : ValidZKP := generateZKP ...
    let unknownZKP := Network.sendZKPoverHTTPSorBLE zkp

    -- 受信側（Verifier）
    match Network.receiveZKPoverHTTPSorBLE unknownZKP someRelation with
    | some validZKP =>
        -- 検証成功: ValidZKPとして使用可能
        acceptProof validZKP
    | none =>
        -- 検証失敗: 拒否
        error "Invalid ZKP received"
    ```
-/
def receiveZKPoverHTTPSorBLE (zkp : UnknownZKP) (_relation : Relation) : Option ValidZKP :=
  match zkp with
  | UnknownZKP.valid validZKP => some validZKP
  | UnknownZKP.invalid _ => none

-- ## DIDComm 通信関数

/-- DIDCommメッセージ送信: ValidDID + オプショナルなDIDDocument/VCs/ZKPを送信

    **設計思想（DIDComm v2.1 + did:amt仕様に準拠）:**
    - メッセージには送信者のDID文字列を含む
    - **did:amt制約**: Holderは通常、DIDDocumentも送信する（Optionalだが推奨）
    - ECDH-1PUで暗号化（送信者のSK + 受信者のPKで認証付き暗号化）

    **使用例:**
    1. Issuer → Holder: VCの発行
       ```lean
       let msg := Network.sendViaDIDComm issuerDID (some issuerDoc) [newVC] none
       ```

    2. Verifier → Holder: Verifier認証（複数のVerifierVCを送信）
       ```lean
       let msg := Network.sendViaDIDComm verifierDID (some verifierDoc)
         verifierVCs (some verifierAuthZKP)
       ```

    3. Holder → Verifier: HolderがVCに基づくZKPを送信
       ```lean
       let msg := Network.sendViaDIDComm holderDID (some holderDoc) [] (some holderCredentialZKP)
       ```

    **did:amt注意点:**
    - 受信側がDIDDocumentを持っていない場合、`senderDoc`を`some doc`で送信する必要がある
    - トラストアンカーのような公開されたDIDDocumentの場合は、`none`でも可
-/
noncomputable def sendViaDIDComm
    (senderDID : ValidDID)
    (senderDoc : Option ValidDIDDocument)
    (vcs : List ValidVC)
    (zkp : Option ValidZKP) : DIDCommMessageSend :=
  { senderDID := senderDID, senderDoc := senderDoc, vcs := vcs, zkp := zkp }

/-- DIDCommメッセージ受信: UnknownDID + オプショナルなUnknownDIDDocument + UnknownVCs/UnknownZKPを受信

    **設計思想（信頼境界）:**
    - DID: メッセージから取得するが、未検証（UnknownDID）
    - DIDDocument: メッセージから取得するが、所有権未検証（Option UnknownDIDDocument）
    - VCs/ZKP: 受信側はこれを信頼できないため、Unknownとして扱う

    **型システムによる保証:**
    すべてのデータがUnknownとして受け取られるため、検証を忘れることができない。
    型システムが検証を強制する。

    **実装:**
    この関数は通信プロセスを抽象化したもの：
    1. シリアライズ → DIDComm送信 → DIDComm受信 → デシリアライズ
    2. 復号化（ECDH-1PU）
    3. **did:amt制約**: DID解決は不可、送信側がDIDDocumentを含める必要がある

    すべてのデータは受信側で未検証として扱われる。
-/
noncomputable def receiveViaDIDComm (msg : DIDCommMessageSend) : DIDCommMessageReceive :=
  -- 送信側のValidDIDは、受信側から見れば未検証なのでUnknownDIDとして扱う
  let senderDID := UnknownDID.valid msg.senderDID
  -- 送信側のValidDIDDocumentは、受信側から見れば所有権未検証なのでUnknownDIDDocumentとして扱う
  let senderDoc := msg.senderDoc.map UnknownDIDDocument.valid
  { senderDID := senderDID,
    senderDoc := senderDoc,
    vcs := msg.vcs.map UnknownVC.valid,
    zkp := msg.zkp.map UnknownZKP.valid }

-- ## 受信側の検証パターン

/-- 受信したVCを検証してValidVCに変換

    **DIDComm検証フロー:**
    1. DIDCommメッセージを受信
    2. VCs（List UnknownVC）を取り出す
    3. 各VCに対して署名検証を行う
    4. 検証成功ならValidVCとして使用可能

    **使用例:**
    ```lean
    -- 受信側（Holder）
    let receivedMsg := Network.receiveViaDIDComm sentMsg
    -- 各VCを検証
    let validVCs := receivedMsg.vcs.filterMap Network.verifyReceivedVC
    -- 検証成功したVCのみを処理
    for validVC in validVCs do
      Holder.storeCredential wallet validVC ...
    ```
-/
def verifyReceivedVC (vc : UnknownVC) : Option ValidVC :=
  match vc with
  | UnknownVC.valid validVC => some validVC
  | UnknownVC.invalid _ => none

/-- 受信したZKPを検証してValidZKPに変換

    **DIDComm検証フロー:**
    1. DIDCommメッセージを受信
    2. ZKP（Option UnknownZKP）を取り出す
    3. 暗号的検証を行う
    4. 検証成功ならValidZKPとして使用可能
-/
def verifyReceivedZKP (zkp : UnknownZKP) (_relation : Relation) : Option ValidZKP :=
  match zkp with
  | UnknownZKP.valid validZKP => some validZKP
  | UnknownZKP.invalid _ => none

end Network

-- ## 通信レイヤーの安全性定理

namespace Network

-- ### ZKP over HTTPS/BLE の定理

/-- Theorem: 正しく送信されたZKPは検証に成功する（ZKP over HTTPS/BLEの完全性）

    **設計思想:**
    - 送信側がValidZKPを送信し、改ざんされずに届いた場合、検証に成功する
    - これは通信レイヤーの理想的なケース

    **現実:**
    - 攻撃者が改ざんした場合、`UnknownZKP.invalid`が届く
    - その場合、`receiveZKPoverHTTPSorBLE`は`none`を返す（健全性）
-/
theorem send_receive_zkp_over_https_ble_completeness :
  ∀ (zkp : ValidZKP) (relation : Relation),
    let unknownZKP := sendZKPoverHTTPSorBLE zkp
    receiveZKPoverHTTPSorBLE unknownZKP relation = some zkp := by
  intro zkp relation
  unfold sendZKPoverHTTPSorBLE receiveZKPoverHTTPSorBLE
  rfl

/-- Theorem: ZKP over HTTPS/BLEの型安全性

    **保証:**
    受信側は必ずUnknownZKPを受け取るため、検証を忘れることができない。
    型システムが検証を強制する。

    **形式化:**
    - `sendZKPoverHTTPSorBLE : ValidZKP → UnknownZKP`（検証済み → 未検証）
    - `receiveZKPoverHTTPSorBLE : UnknownZKP → Relation → Option ValidZKP`（検証必須）
-/
theorem zkp_over_https_ble_type_safety :
  -- 送信側: ValidZKPを送る
  (∀ (zkp : ValidZKP),
    ∃ (unknownZKP : UnknownZKP), unknownZKP = sendZKPoverHTTPSorBLE zkp) ∧
  -- 受信側: UnknownZKPを受け取り、検証が必須
  (∀ (unknownZKP : UnknownZKP) (validZKP : ValidZKP) (relation : Relation),
    receiveZKPoverHTTPSorBLE unknownZKP relation = some validZKP →
    unknownZKP = UnknownZKP.valid validZKP) := by
  constructor
  · -- 送信側
    intro zkp
    exact ⟨sendZKPoverHTTPSorBLE zkp, rfl⟩
  · -- 受信側
    intro unknownZKP validZKP relation h_some
    unfold receiveZKPoverHTTPSorBLE at h_some
    cases unknownZKP with
    | valid zkp =>
        simp at h_some
        rw [← h_some]
    | invalid _ =>
        simp at h_some

-- ### DIDComm の定理

/-- Theorem: 正しく送信されたDIDCommメッセージは正しく受信される（DIDCommの完全性）

    **設計思想（DIDComm v2.1 + did:amt仕様に準拠）:**
    - 送信側がValidなデータを送信し、改ざんされずに届いた場合、正しく受信される
    - DID: メッセージから取得するが、未検証（UnknownDID）
    - DIDDocument: メッセージから取得するが、所有権未検証（Option UnknownDIDDocument）
    - VCs/ZKP: Unknownとして受信され、受信側で検証が必要

    **現実:**
    - 攻撃者が改ざんした場合、`UnknownDID.invalid`、`UnknownDIDDocument.invalid`、
      `UnknownVC.invalid`、`UnknownZKP.invalid`が届く
    - その場合、検証関数は`none`を返す（健全性）
-/
theorem send_receive_didcomm_completeness :
  ∀ (did : ValidDID) (doc : Option ValidDIDDocument) (vcs : List ValidVC) (zkp : Option ValidZKP),
    let sentMsg := sendViaDIDComm did doc vcs zkp
    let receivedMsg := receiveViaDIDComm sentMsg
    -- DIDはUnknownとして受信される（理想的なケースではvalid）
    receivedMsg.senderDID = UnknownDID.valid did ∧
    -- DIDDocumentはUnknownとして受信される（送信された場合）
    (∀ (validDoc : ValidDIDDocument),
      doc = some validDoc →
      receivedMsg.senderDoc = some (UnknownDIDDocument.valid validDoc)) ∧
    -- VCsはUnknownとして受信され、検証可能
    receivedMsg.vcs = vcs.map UnknownVC.valid ∧
    -- ZKPはUnknownとして受信され、検証可能
    (∀ (validZKP : ValidZKP),
      zkp = some validZKP →
      receivedMsg.zkp = some (UnknownZKP.valid validZKP)) := by
  intro did doc vcs zkp
  constructor
  · -- DID
    unfold sendViaDIDComm receiveViaDIDComm
    simp
  constructor
  · -- DIDDocument
    intro validDoc h_doc
    unfold sendViaDIDComm receiveViaDIDComm
    simp [h_doc]
  constructor
  · -- VCs
    unfold sendViaDIDComm receiveViaDIDComm
    simp
  · -- ZKP
    intro validZKP h_zkp
    unfold sendViaDIDComm receiveViaDIDComm
    simp [h_zkp]

/-- Theorem: DIDCommの型安全性（DID/DIDDocument）

    **保証（DIDComm v2.1 + did:amt仕様に準拠）:**
    DIDCommでは、DIDもDIDDocumentも受信側でUnknownとして扱われるため、
    検証を忘れることができない。型システムが検証を強制する。

    **形式化:**
    - `sendViaDIDComm : ValidDID → Option ValidDIDDocument →
      List ValidVC → ... → DIDCommMessageSend`
    - `receiveViaDIDComm : DIDCommMessageSend → DIDCommMessageReceive`
    - 受信側では`UnknownDID`と`Option UnknownDIDDocument`として扱う
-/
theorem didcomm_did_diddocument_safety :
  ∀ (did : ValidDID) (doc : Option ValidDIDDocument) (vcs : List ValidVC) (zkp : Option ValidZKP),
    let sentMsg := sendViaDIDComm did doc vcs zkp
    let receivedMsg := receiveViaDIDComm sentMsg
    -- DIDはUnknownとして受信される
    receivedMsg.senderDID = UnknownDID.valid did ∧
    -- DIDDocumentも（送信された場合）Unknownとして受信される
    (∀ (validDoc : ValidDIDDocument),
      doc = some validDoc →
      receivedMsg.senderDoc = some (UnknownDIDDocument.valid validDoc)) := by
  intro did doc vcs zkp
  constructor
  · unfold sendViaDIDComm receiveViaDIDComm
    simp
  · intro validDoc h_doc
    unfold sendViaDIDComm receiveViaDIDComm
    simp [h_doc]

/-- Theorem: DIDCommの型安全性（VCs/ZKP）

    **保証:**
    DIDCommでVCs/ZKPを送信する場合、受信側は必ずUnknownとして受け取るため、
    検証を忘れることができない。型システムが検証を強制する。

    **形式化:**
    - VCs: `List ValidVC → List UnknownVC`（検証済み → 未検証）
    - ZKP: `Option ValidZKP → Option UnknownZKP`（検証済み → 未検証）
    - 受信側は`verifyReceivedVC`/`verifyReceivedZKP`で検証必須
-/
theorem didcomm_vc_zkp_type_safety :
  -- VCsの型安全性
  (∀ (did : ValidDID) (doc : Option ValidDIDDocument) (vcs : List ValidVC) (zkp : Option ValidZKP),
    let sentMsg := sendViaDIDComm did doc vcs zkp
    let receivedMsg := receiveViaDIDComm sentMsg
    receivedMsg.vcs = vcs.map UnknownVC.valid) ∧
  -- ZKPの型安全性
  (∀ (did : ValidDID) (doc : Option ValidDIDDocument) (vcs : List ValidVC) (zkp : ValidZKP),
    let sentMsg := sendViaDIDComm did doc vcs (some zkp)
    let receivedMsg := receiveViaDIDComm sentMsg
    ∃ (unknownZKP : UnknownZKP),
      receivedMsg.zkp = some unknownZKP ∧
      ∀ (relation : Relation), verifyReceivedZKP unknownZKP relation = some zkp) := by
  constructor
  · -- VCs
    intro did doc vcs zkp
    unfold sendViaDIDComm receiveViaDIDComm
    rfl
  · -- ZKP
    intro did doc vcs zkp
    unfold sendViaDIDComm receiveViaDIDComm verifyReceivedZKP
    simp

end Network
