# マルチデバイス対応仕様（Multi-Device Support）- クレーム個別転送版

**Version**: 2.0
**Date**: 2025-01-13

## 目次
1. [概要](#1-概要)
2. [設計思想](#2-設計思想)
3. [ユースケース](#3-ユースケース)
4. [DIDComm通信プロトコル](#4-didcomm通信プロトコル)
5. [クレーム転送メカニズム](#5-クレーム転送メカニズム)
6. [ZKP効率化](#6-zkp効率化)
7. [セキュリティ考慮事項](#7-セキュリティ考慮事項)
8. [実装ガイドライン](#8-実装ガイドライン)

---

## 1. 概要

AMATELUSプロトコルにおけるマルチデバイス対応は、単一のHolder（保持者）が複数のデバイス上で異なるDIDを持つウォレットを運用し、デバイス間で**クレーム単位**で安全に転送する機能を提供します。

### 1.1 背景

身分証明系のVCは以下の特性を持ちます：
- **現地受領の必要性**: 市役所、警察署など対面での発行が多い
- **スマホでの受領**: 現地ではスマホで受領することが一般的
- **PCでの利用ニーズ**: 自宅からAMATELUSネットワークに参加する際にはPCを使用

これらのニーズを満たすため、マルチデバイス対応が必須となります。

### 1.2 設計原則

1. **秘密鍵の非共有**: デバイス間で秘密鍵は転送しない
2. **クレーム単位の転送**: VCではなくクレームを個別に転送
3. **二重署名**: issuer署名 + original subject転送署名
4. **W3C標準準拠**: `holder ≠ credentialSubject` をサポート
5. **DIDComm使用**: 標準的なDID間通信プロトコルを使用
6. **エンドツーエンド暗号化**: 転送データは常に暗号化
7. **プロトコルレベルのルール**: 署名のないクレームは無視される

### 1.3 V2.0の主要変更点（V1.0からの移行）

**V1.0（VC転送版）の問題点**:
- VC全体を転送するため、ZKP生成時にすべてのクレームを入力する必要がある
- 不要なクレームまでZKP回路に含まれ、回路サイズが肥大化
- 計算コストが高く、プライバシー保護にも課題

**V2.0（クレーム個別転送版）の利点**:
- 必要なクレームのみをZKP回路に入力可能
- 回路サイズの最小化、計算コストの削減
- プライバシー保護の強化（不要なクレームを扱わない）
- 二重署名により完全なセキュリティ保証

---

## 2. 設計思想

### 2.1 トラストチェーンとの違い

AMATELUSには2つの異なる機能があります：

| 機能 | 用途 | メカニズム | DID関係 |
|------|------|-----------|---------|
| **トラストチェーン** | Schema継承、権限委譲 | DelegationChain | 異なる組織のDID |
| **マルチデバイス** | クレームの共有 | クレーム個別転送 | 同一Holderの異なるDID |

### 2.2 クレームの転送経路

AMATELUSプロトコルでは、クレームは以下の2つの経路で転送されます：

```
1. Issuer → Holder_A (初回発行)
2. Holder_A → Holder_B (クレーム単位の転送) ← 本仕様の対象
```

外部への提出は常にZKPのみで行われ、クレームそのものは外部に出ません。

### 2.3 クレーム構造

すべてのクレームは必ずissuerの署名を持ちます：

```lean
structure SignedClaim where
  content : String                      -- クレームの内容
  delegationChain : Option DelegationChain  -- 委任チェーン（任意）
  issuerSignature : Signature           -- Issuerによる署名（必須）
```

**プロトコルレベルのルール**: 署名のないクレームは無視されます。

### 2.4 転送されたクレーム構造

デバイス間で転送されたクレームは、二重署名を持ちます：

```lean
structure TransferredClaim where
  originalClaim : SignedClaim           -- 元のクレーム（issuer署名付き）
  originalSubjectDID : ValidDID         -- 元の所有者DID
  currentHolderDID : ValidDID           -- 現在の保持者DID
  transferProof : Signature             -- Original subjectによる転送署名
  transferredAt : Nat                   -- 転送日時
```

**二重署名の役割**:
1. **issuerSignature**: クレームの真正性を保証（市役所が発行）
2. **transferProof**: クレーム所有権と転送の同意を証明（DID_Aが所有・転送）

### 2.5 W3C標準との整合性

W3C VC標準では、`holder`（VCを保持する者）と`credentialSubject`（VCが言及する主体）は異なっても良いとされています。

クレーム個別転送版では：
- `issuer`の署名は変更されない（元のissuerが発行）
- `originalSubjectDID`は変更されない（元のDIDを維持）
- `currentHolderDID`は新しいデバイスのDID
- PCのウォレットが保持し、ZKP生成に使用可能

---

## 3. ユースケース

### 3.1 市役所での住民票VC受領

```
1. Aliceはスマホを持って市役所に行く
2. 市役所職員がスマホのDID (did:amt:alice_smartphone) を確認
3. 市役所が住民票VCをスマホのウォレットに発行
4. スマホのウォレットがVCを受領・保存
```

### 3.2 自宅PCへのクレーム転送

```
5. Aliceが自宅に帰宅
6. PCのウォレット (did:amt:alice_pc) を起動
7. スマホのウォレットからPCのウォレットにクレーム転送リクエスト
8. スマホのウォレットが転送署名を生成（DID_Aの秘密鍵で署名）
9. DIDCommプロトコルでクレームを暗号化転送
10. PCのウォレットがクレームを受領・検証・保存
11. PCからAMATELUSネットワークに参加可能に
```

### 3.3 クレームの利用（ZKP生成）

PCのウォレットでZKPを生成する場合：

```json
{
  "public_inputs": {
    "holder_did": "did:amt:alice_pc",
    "age_gte": 20,
    "residence": "Tokyo"
  },
  "proof": "..."
}
```

**重要**:
- ZKPの生成はPCのウォレットが行う
- `originalSubjectDID`（元のスマホのDID）は秘密入力
- `currentHolderDID`（PCのDID）は公開入力
- issuerの署名とtransfer署名の両方をZKP内で検証
- **必要なクレームのみを入力**（他のクレームは不要）

---

## 4. DIDComm通信プロトコル

### 4.1 DIDCommの概要

**DIDComm（DID Communication）**は、DID間の安全な通信を可能にする標準プロトコルです：

- **仕様**: [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/)
- **特徴**:
  - エンドツーエンド暗号化
  - 認証済みメッセージング
  - トランスポート非依存（HTTP, WebSocket, Bluetooth等）

### 4.2 DIDCommメッセージ構造

#### 4.2.1 クレーム転送リクエスト

```json
{
  "type": "https://amatelus.org/protocols/claim-transfer/2.0/request",
  "id": "uuid-1234-5678",
  "from": "did:amt:alice_pc",
  "to": "did:amt:alice_smartphone",
  "created_time": 1673568000,
  "body": {
    "request_type": "filtered_claims",
    "filters": {
      "content_patterns": ["name", "address"],
      "issuer": "did:amt:municipality123"
    }
  }
}
```

#### 4.2.2 クレーム転送レスポンス

```json
{
  "type": "https://amatelus.org/protocols/claim-transfer/2.0/response",
  "id": "uuid-8765-4321",
  "from": "did:amt:alice_smartphone",
  "to": "did:amt:alice_pc",
  "created_time": 1673568010,
  "thid": "uuid-1234-5678",
  "body": {
    "transferred_claims": [
      {
        "original_claim": {
          "content": "{\"name\": \"Alice\", \"address\": \"Tokyo\"}",
          "delegation_chain": null,
          "issuer_signature": {
            "type": "Ed25519Signature2020",
            "created": "2025-01-10T00:00:00Z",
            "verification_method": "did:amt:municipality123#keys-1",
            "proof_value": "base64encodedIssuerSignature..."
          }
        },
        "original_subject_did": "did:amt:alice_smartphone",
        "current_holder_did": "did:amt:alice_pc",
        "transfer_proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-01-13T12:00:00Z",
          "verification_method": "did:amt:alice_smartphone#keys-1",
          "proof_value": "base64encodedTransferSignature..."
        },
        "transferred_at": 1673568010
      }
    ],
    "success": true
  }
}
```

### 4.3 認証フロー

#### 4.3.1 デバイスペアリング

初回接続時に、2つのウォレットをペアリングします：

```
1. PC: QRコードを表示（did:amt:alice_pc + 一時トークン）
2. スマホ: QRコードをスキャン
3. スマホ: DIDComm接続リクエストを送信
4. PC: ユーザーに承認を求める
5. ユーザー: PCで承認
6. 両デバイス: 相手のDIDを信頼リストに追加
```

#### 4.3.2 相互認証

ペアリング済みデバイス間の通信：

```
1. リクエスト側: DIDCommメッセージに署名
2. レスポンス側: 署名を検証し、信頼リストを確認
3. レスポンス側: 暗号化されたレスポンスを送信
4. リクエスト側: レスポンスを復号・検証
```

---

## 5. クレーム転送メカニズム

### 5.1 転送されるデータ

クレーム転送時に送信されるデータ：

```json
{
  "original_claim": {
    "content": "{\"name\": \"Alice\", \"address\": \"Tokyo\"}",
    "delegation_chain": null,
    "issuer_signature": "..."
  },
  "original_subject_did": "did:amt:alice_smartphone",
  "current_holder_did": "did:amt:alice_pc",
  "transfer_proof": "...",
  "transferred_at": 1673568010
}
```

**変更されないもの**:
- `original_claim.content`: クレームの内容
- `original_claim.issuer_signature`: issuerの署名
- `original_subject_did`: 元のHolder DID（スマホ）

**追加されるもの**:
- `transfer_proof`: original subjectによる転送署名（必須）
- `current_holder_did`: 現在の保持者DID（PC）
- `transferred_at`: 転送日時

### 5.2 転送署名の生成

スマホのウォレットが転送署名を生成する処理：

```lean
def prepareClaimTransfer
    (claim : SignedClaim)
    (originalSubjectDID : ValidDID)
    (currentHolderDID : ValidDID)
    (timestamp : Nat) : TransferredClaim :=
  -- 1. 転送メッセージを構築
  let message := encodeTransferMessage claim.content
                   originalSubjectDID currentHolderDID

  -- 2. Original subjectの秘密鍵で署名
  let transferProof := sign message originalSubjectSecretKey

  -- 3. TransferredClaimを生成
  {
    originalClaim := claim,
    originalSubjectDID := originalSubjectDID,
    currentHolderDID := currentHolderDID,
    transferProof := transferProof,
    transferredAt := timestamp
  }
```

### 5.3 受信ウォレットでの検証

PCのウォレットは受信したクレームを検証：

```lean
def validateClaim
    (tc : TransferredClaim)
    (issuerDID : ValidDID)
    (trustedAnchors : List ValidDID) : Bool :=
  -- 1. Issuerの署名を検証
  let issuerSigValid := tc.originalClaim.verify issuerDID

  -- 2. Original subjectの転送署名を検証
  let transferSigValid := tc.verifyTransferProof

  -- 3. Issuerが信頼されているか確認
  let issuerTrusted := trustedAnchors.contains issuerDID

  issuerSigValid && transferSigValid && issuerTrusted
```

### 5.4 受信ウォレットでの保存

PCのウォレットは受信したクレームを以下の構造で保存：

```json
{
  "claim_id": "uuid-claim-001",
  "original_claim": {
    "content": "{\"name\": \"Alice\"}",
    "issuer_signature": "..."
  },
  "original_subject_did": "did:amt:alice_smartphone",
  "current_holder_did": "did:amt:alice_pc",
  "transfer_proof": "...",
  "storage_metadata": {
    "received_at": "2025-01-13T12:00:00Z",
    "received_from": "did:amt:alice_smartphone",
    "issuer_did": "did:amt:municipality123"
  }
}
```

---

## 6. ZKP効率化

### 6.1 クレーム個別転送の利点

**V1.0（VC転送版）の問題**:
```
住民票VCに5つのクレーム（name, address, birthDate, residence, age）が含まれる場合、
年齢証明のZKPを生成する際に、すべてのクレームをZKP回路に入力する必要がある。
```

**V2.0（クレーム個別転送版）の利点**:
```
必要なクレーム（age）のみをZKP回路に入力可能。
回路サイズが最小化され、計算コストが削減される。
```

### 6.2 ZKP生成時の処理

PCのウォレットがZKPを生成する際：

```lean
structure ZKPSecretInputsForTransferredClaim where
  claimContent : String              -- クレームの内容（秘密）
  issuerSignature : Signature        -- Issuerの署名（ZKP内で検証）
  transferSignature : Signature      -- Transfer署名（ZKP内で検証）
  originalSubjectDID : ValidDID      -- Original subject DID（秘密）

structure ZKPPublicInputsForTransferredClaim where
  currentHolderDID : ValidDID        -- 現在の保持者DID（公開）
  publicAttributes : List (String × String)  -- 公開するクレーム属性
```

**ZKP回路内の検証**:
1. `issuerSignature`が有効（市役所が発行）
2. `transferSignature`が有効（DID_Aが所有・転送）
3. `originalSubjectDID == claim内のsubject`（整合性）

### 6.3 計算コストの比較

| 方式 | 入力クレーム数 | 回路サイズ | 計算コスト |
|------|-------------|----------|----------|
| **V1.0（VC転送）** | 全クレーム（5個） | 大 | 高 |
| **V2.0（クレーム個別転送）** | 必要なクレームのみ（1個） | 小 | 低 |

### 6.4 プライバシー保護の強化

クレーム個別転送により：
- 不要なクレームをZKP回路に含めない
- 不要なクレームの存在自体を隠蔽可能
- 選択的開示の粒度が向上

---

## 7. セキュリティ考慮事項

### 7.1 秘密鍵の非共有

**重要原則**: デバイス間で秘密鍵は絶対に転送しない

- 各デバイスは独立したDIDと秘密鍵ペアを持つ
- クレームデータ（issuerの署名 + 転送署名）のみを転送
- 秘密鍵漏洩時の影響範囲を限定

### 7.2 二重署名セキュリティ

クレーム個別転送は二重署名により完全なセキュリティを保証：

1. **issuerSignature**:
   - クレームの真正性を保証
   - Issuer（市役所）が発行したことを証明
   - 改ざん防止

2. **transferProof**:
   - クレーム所有権を証明
   - Original subject（DID_A）が所有していることを証明
   - 転送の同意を証明

**セキュリティ保証**:
```lean
theorem claim_transfer_preserves_issuer_signature :
  ∀ (claim : SignedClaim) (originalSubjectDID currentHolderDID : ValidDID)
    (timestamp : Nat),
  let tc := prepareClaimTransfer claim originalSubjectDID currentHolderDID timestamp
  tc.originalClaim.issuerSignature = claim.issuerSignature
```

### 7.3 エンドツーエンド暗号化

すべてのクレーム転送はDIDCommの暗号化機能を使用：

```
1. 送信側: 受信側の公開鍵で暗号化
2. トランスポート層: TLS等の追加暗号化（任意）
3. 受信側: 自身の秘密鍵で復号
```

### 7.4 デバイス認証

#### 7.4.1 ペアリング時の認証

- QRコード + 一時トークン
- ユーザーによる明示的な承認
- 信頼リストへの登録

#### 7.4.2 転送時の認証

- 信頼リストの確認
- DIDComm署名検証
- タイムスタンプ検証（リプレイ攻撃防止）

### 7.5 クレームの整合性検証

受信ウォレットは以下を検証：

```lean
def validateClaim
    (tc : TransferredClaim)
    (issuerDID : ValidDID)
    (trustedAnchors : List ValidDID) : Bool :=
  -- 1. Issuerの署名を検証
  let issuerSigValid := tc.originalClaim.verify issuerDID

  -- 2. Original subjectの転送署名を検証
  let transferSigValid := tc.verifyTransferProof

  -- 3. Issuerが信頼されているか確認
  let issuerTrusted := trustedAnchors.contains issuerDID

  issuerSigValid && transferSigValid && issuerTrusted
```

### 7.6 中間者攻撃（MITM）対策

DIDCommプロトコルによる対策：

1. **認証付き暗号化（AEAD）**: メッセージの改ざん検出
2. **DID署名**: 送信者の真正性保証
3. **ペアリング時の確認**: ユーザーによる承認
4. **二重署名**: issuer署名 + 転送署名による完全性保証

### 7.7 プライバシー保護

- **クレーム転送は秘密**: 第三者に転送の事実を知られない
- **originalSubjectDIDの保護**: ZKP生成時に秘密入力として扱う
- **選択的転送**: 必要なクレームのみを転送
- **メタデータの分離**: 転送履歴はローカルのみ保存

### 7.8 プロトコルレベルの保証

**署名のないクレームは無視される**:
- すべてのクレームは必ずissuer署名を持つ
- 転送されたクレームは必ず転送署名を持つ
- 署名のないクレームはプロトコルレベルで無視
- 改ざん試行は自動的に失敗

---

## 8. 実装ガイドライン

### 8.1 ウォレット実装の要件

#### 8.1.1 必須機能

1. **DIDComm対応**
   - DIDComm v2.0プロトコルの実装
   - エンドツーエンド暗号化サポート

2. **デバイス管理**
   - 信頼済みデバイスリストの管理
   - ペアリング機能（QRコード等）

3. **クレーム転送機能**
   - クレーム送信（フィルタリング対応）
   - 転送署名の生成（original subjectの秘密鍵）
   - クレーム受信（二重署名検証機能付き）

4. **ZKP生成の拡張**
   - `currentHolderDID`の公開入力対応
   - `originalSubjectDID`の秘密入力対応
   - issuer署名とtransfer署名の両方をZKP内で検証
   - 必要なクレームのみを入力（他のクレームは不要）

5. **署名検証**
   - issuer署名の検証
   - 転送署名の検証
   - 署名のないクレームの拒否（プロトコルレベル）

#### 8.1.2 推奨機能

1. **選択的転送**
   - 特定のクレームのみを転送
   - content pattern別のフィルタリング
   - issuer別のフィルタリング

2. **転送履歴**
   - いつ、どのデバイスに転送したかの記録
   - 転送の取り消し（リボーク通知）

3. **自動同期**
   - 新規クレームの自動転送
   - デバイス間の同期設定

4. **クレーム管理**
   - クレーム単位での保存・検索
   - 委任チェーンの表示
   - ZKP生成時のクレーム選択UI

### 7.2 トランスポート層の選択

DIDCommは複数のトランスポートをサポート：

| トランスポート | 用途 | 特徴 |
|--------------|------|------|
| **HTTP/HTTPS** | インターネット経由 | クラウド中継可能 |
| **WebSocket** | リアルタイム通信 | 双方向通信 |
| **Bluetooth** | ローカル通信 | インターネット不要 |
| **NFC** | 近接通信 | 非常に短距離 |

推奨構成：
```
- 同一ネットワーク内: WebSocket（高速）
- 異なるネットワーク: HTTPS（安定性）
- オフライン: Bluetooth（インターネット不要）
```

### 7.3 エラーハンドリング

#### 7.3.1 転送失敗時の処理

```json
{
  "type": "https://amatelus.org/protocols/vc-transfer/1.0/error",
  "id": "uuid-error-001",
  "from": "did:amt:alice_smartphone",
  "to": "did:amt:alice_pc",
  "thid": "uuid-1234-5678",
  "body": {
    "error_code": "SIGNATURE_VERIFICATION_FAILED",
    "error_message": "VC signature verification failed",
    "details": {
      "vc_id": "uuid-vc-001",
      "issuer": "did:amt:municipality123"
    }
  }
}
```

#### 7.3.2 リトライロジック

```
1. 転送失敗を検出
2. 指数バックオフでリトライ（最大3回）
3. 失敗時はユーザーに通知
4. ログに記録
```

### 8.4 テスト指針

#### 8.4.1 機能テスト

- ペアリング成功/失敗
- クレーム転送成功/失敗
- issuer署名検証
- 転送署名検証
- 二重署名検証
- フィルタリング機能
- 署名のないクレームの拒否

#### 8.4.2 セキュリティテスト

- MITM攻撃シミュレーション
- 不正なクレームの拒否
- 署名改ざん検出
- 信頼されていないデバイスの拒否
- 署名のないクレームの自動拒否

#### 8.4.3 パフォーマンステスト

- 大量クレーム転送時の性能
- 暗号化/復号のオーバーヘッド
- ネットワーク遅延への対応
- ZKP生成時間の比較（V1.0 vs V2.0）

#### 8.4.4 ZKP効率化テスト

- クレーム数による回路サイズの比較
- 必要なクレームのみを入力した場合の性能
- 全クレームを入力した場合との比較

---

## 9. 将来の拡張

### 9.1 クラウド同期

信頼できるクラウドサービスを中継に使用：

```
スマホ → [暗号化] → クラウド → [復号] → PC
```

**要件**:
- エンドツーエンド暗号化必須
- クラウドはクレームの内容を知ることができない
- ゼロ知識証明ベースのバックアップ
- クレーム単位での同期

### 9.2 グループウォレット

家族や組織内での安全なクレーム共有：

```
親のウォレット ⇄ 子供のウォレット（保護者機能）
企業ウォレット ⇄ 従業員ウォレット（役職証明）
```

**要件**:
- クレーム単位での共有制御
- 二重署名による完全性保証
- 選択的開示の粒度向上

### 9.3 条件付き転送

特定の条件下でのみクレーム転送を許可：

```json
{
  "transfer_policy": {
    "allowed_devices": ["did:amt:alice_pc", "did:amt:alice_tablet"],
    "allowed_time": "09:00-18:00",
    "require_biometric": true,
    "max_transfers": 3,
    "allowed_claims": ["name", "address"]
  }
}
```

### 9.4 委任チェーンとの統合

N階層委任とクレーム個別転送の組み合わせ：

```
- 委任チェーンを含むクレームの転送
- 転送先での委任チェーンの検証
- ZKP生成時の効率化（必要なクレームのみ）
```

---

## 10. 参考文献

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/)
- [AMATELUS Trust Chain Specification](./TrustChain.md)
- [AMATELUS Privacy Specification](./Privacy.md)
- [AMATELUS MultiDevice Implementation (Lean 4)](../AMATELUS/MultiDevice.lean)

---

## 11. 形式検証

AMATELUS/MultiDevice.leanで形式的に証明された定理：

1. **claim_transfer_preserves_issuer_signature**
   - クレーム転送時にissuerの署名は保持される

2. **claim_transfer_preserves_content**
   - クレーム転送時にクレーム内容は保持される

3. **transferred_claim_has_transfer_proof**
   - 転送されたクレームは必ず転送署名を持つ

4. **device_trust_symmetric**
   - デバイス信頼検証の対称性

5. **valid_claim_stays_valid_after_transfer**
   - 有効なクレームは転送後も有効

これらの定理により、クレーム個別転送のセキュリティが形式的に保証されています。

---

## 変更履歴

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-13 | 初版作成（VC転送版） |
| 2.0 | 2025-01-13 | クレーム個別転送版に変更、二重署名、ZKP効率化 |
