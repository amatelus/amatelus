# AMATELUS Merkle Tree Revocation Specification

**Status**: AMATELUS Protocol Specification (Draft)
**Version**: 1.0.0
**Base Specifications**:
- W3C Verifiable Credentials Data Model 2.0
- W3C Bitstring Status List (参考)
- AMATELUS ZKP Framework

---

## 1. Abstract

このドキュメントは、AMATELUSプロトコルにおける**Merkle Treeベースの失効確認フロー**の詳細な仕様を定義します。

### 1.1 背景と動機

W3C Bitstring Status Listは、失効確認のために`statusListIndex`を公開する必要があり、**ゼロ知識証明（ZKP）との根本的な矛盾**が存在します：

```
従来方式（Bitstring Status List）:
  Holder → statusListIndex → Issuer

  問題点:
  - statusListIndexの公開 = どのVCか特定される
  - ZKPのゼロ知識性が崩壊
  - プライバシー保護が不可能
```

### 1.2 設計目標

本仕様は以下の目標を達成します：

1. **ゼロ知識性の保持**: どのVCを提示しているか特定されない
2. **失効確認の安全性**: 失効されたVCでZKP生成が不可能
3. **スケーラビリティ**: O(log N)の計算量（N = アクティブVC数）
4. **災害時の可用性**: オフライン時は失効確認スキップ可能
5. **W3C VC互換**: credentialStatus拡張として実装
6. **個人Issuerの対応**: ウェブサーバーを管理できない個人Issuerも運用可能

### 1.3 個人Issuerの課題と解決策

#### 1.3.1 課題

Merkle Tree方式の失効確認は、Issuerが中央集権的なウェブサーバー（Merkle Root公開用）を運営する必要があります：

```
問題点:
  - 個人IssuerはHTTPサーバーを常時稼働できない可能性が高い
  - サーバー管理コスト（ドメイン、SSL証明書、インフラ維持費）
  - 24時間365日の可用性保証が困難
```

**従来設計の不備**:
- Holderが失効確認結果をZKPに含めなかった場合、Verifierはそもそも失効確認可能なVCかどうかを知ることができない
- これにより、失効確認をスキップされても検出不可能

#### 1.3.2 解決策：失効確認可否フラグ

**設計原則**:
```
Issuerが発行時に必ず失効確認の可否を含める（revocationEnabledフラグ）
  ↓
HolderはZKP生成時、このフラグをZKP回路に入力
  ↓
Verifierは数学的に失効確認の有無を判定可能
```

**具体的な実装**:
1. VC発行時、Issuerが`revocationEnabled: true/false`をクレームに含める
2. このフラグはIssuer署名の対象（改ざん不可）
3. ZKP回路内で以下を検証：
   - `revocationEnabled = true` → Merkle証明の検証が必須
   - `revocationEnabled = false` → Merkle証明の検証をスキップ
4. Verifierは`revocationEnabled`の値をZKP公開入力として受け取り、ポリシー判定

**利点**:
- 個人Issuerはサーバー管理不要で`revocationEnabled = false`のVCを発行可能
- Verifierは失効確認の有無を数学的に確認できる（Holderが隠蔽不可）
- 組織Issuerは`revocationEnabled = true`で高い信頼性を提供可能

---

## 2. Architecture Overview

### 2.1 全体フロー

```
┌─────────────────────┐
│   Issuer            │
│                     │
│  1. VC発行          │
│  2. Active List管理  │
│     [H(VC₁), H(VC₂), ...] │
│  3. Merkle Root生成  │
│     root = H(...)   │
│  4. 署名付きRoot公開 │
└──────────┬──────────┘
           │
           │ Merkle Root + Signature
           │ (1時間ごとに更新)
           ▼
┌─────────────────────┐
│   Holder            │
│                     │
│  1. Merkle Root取得  │
│  2. Merkle証明生成   │
│     proof = [h₁, h₂, ...] │
│  3. ZKP生成          │
│     - VC内容（秘密）   │
│     - Merkle証明（秘密） │
│     - Merkle Root（公開） │
└──────────┬──────────┘
           │
           │ ZKP + Merkle Root
           │
           ▼
┌─────────────────────┐
│   Verifier          │
│                     │
│  1. Merkle Root検証  │
│     - Issuer署名確認 │
│  2. タイムスタンプ検証 │
│     - validUntil確認（Issuer署名付き） │
│     - バージョン確認 │
│  3. ZKP検証          │
│     - 回路内でMerkle証明検証 │
│     - VC ∈ Active List → OK │
│     - VC ∉ Active List → NG │
└─────────────────────┘
```

### 2.2 データ構造

#### 2.2.1 Merkle Revocation List

Issuerが管理する失効情報：

```lean
structure MerkleRevocationList where
  /-- 失効していないVCのハッシュリスト -/
  activeVCHashes : List Hash
  /-- Merkle Treeの根 -/
  merkleRoot : Hash
  /-- 更新時刻 -/
  updatedAt : Timestamp
  /-- 有効期限（例: 更新時刻 + 1時間） -/
  validUntil : Timestamp
  /-- バージョン番号（単調増加） -/
  version : Nat
  /-- Issuerの署名 -/
  issuerSignature : Signature
  deriving Repr
```

#### 2.2.2 Merkle証明

Holderが生成する包含証明：

```lean
structure MerkleProof where
  /-- 葉の位置（0-indexed） -/
  leafIndex : Nat
  /-- 証明パス（sibling hashes） -/
  siblingHashes : List Hash
  /-- 木の深さ -/
  treeDepth : Nat
  deriving Repr
```

#### 2.2.3 ZKP秘密入力（失効確認付き）

```lean
structure ZKPSecretInputWithRevocation where
  /-- VCの完全な内容 -/
  vcContent : String
  /-- Issuerの署名 -/
  issuerSignature : Signature
  /-- Merkle証明（revocationEnabled = true の場合のみ必要） -/
  merkleProof : Option MerkleProof
  /-- その他の秘密情報 -/
  additionalSecrets : List (String × String)
  deriving Repr
```

#### 2.2.4 ZKP公開入力（失効確認付き）

```lean
structure ZKPPublicInputWithRevocation where
  /-- 失効確認の有効化フラグ（VCのクレーム内に含まれ、Issuer署名で保護） -/
  revocationEnabled : Bool
  /-- Merkle Root（最新、revocationEnabled = true の場合のみ必要） -/
  merkleRoot : Option Hash
  /-- Merkle Rootのバージョン（revocationEnabled = true の場合のみ必要） -/
  merkleRootVersion : Option Nat
  /-- 公開する属性 -/
  publicAttributes : List (String × String)
  /-- Verifierのnonce -/
  verifierNonce : Nonce
  /-- Holderのnonce -/
  holderNonce : Nonce
  deriving Repr

-- Note: validUntilはZKP公開入力に含めない
--       Verifier側でIssuer署名付きのvalidUntilを検証する
--       これにより、Holderがタイムスタンプを偽造できない

-- Note: revocationEnabledフラグの重要性
--       HolderがこのフラグをZKP公開入力に含めることで、
--       Verifierは失効確認の有無を数学的に判定可能
--       フラグの値はIssuer署名で保護されているため、Holderが改ざん不可
```

---

## 3. Merkle Tree Construction

### 3.1 ハッシュ関数

AMATELUSでは以下のハッシュ関数を使用します：

- **SHA-256**: Merkle Tree構築用（ZKP回路との互換性）
- **SHA3-512**: DID生成等の他の用途（量子安全性）

```
VC_Hash = SHA-256(VC.canonicalized)

where canonicalized =
  JSON-LD Canonicalization Algorithm (URDNA2015)
```

### 3.2 Merkle Tree構築アルゴリズム

```
Input: activeVCHashes = [h₁, h₂, ..., hₙ]
Output: merkleRoot

Algorithm:
  1. パディング（2の累乗に調整）
     if n is not power of 2:
       pad with H("") until next power of 2

  2. レベル0（葉）
     leaves = activeVCHashes + padding

  3. 上方向に計算
     while len(leaves) > 1:
       new_level = []
       for i in range(0, len(leaves), 2):
         parent = SHA-256(leaves[i] || leaves[i+1])
         new_level.append(parent)
       leaves = new_level

  4. 根を返す
     return leaves[0]
```

### 3.3 Merkle証明生成

```
Input:
  - vcHash (証明したいVCのハッシュ)
  - activeVCHashes (全アクティブVCのリスト)
  - merkleRoot (検証用)

Output: MerkleProof

Algorithm:
  1. vcHashの位置を特定
     leafIndex = activeVCHashes.indexOf(vcHash)
     if leafIndex == -1: return None

  2. 証明パスを収集
     siblingHashes = []
     currentIndex = leafIndex
     currentLevel = activeVCHashes + padding

     while len(currentLevel) > 1:
       siblingIndex = currentIndex XOR 1  // 兄弟ノード
       siblingHashes.append(currentLevel[siblingIndex])

       // 親レベルへ移動
       currentIndex = currentIndex / 2
       currentLevel = computeParentLevel(currentLevel)

  3. 証明を返す
     return MerkleProof {
       leafIndex,
       siblingHashes,
       treeDepth = log₂(len(activeVCHashes))
     }
```

### 3.4 Merkle証明検証

```
Input:
  - vcHash (検証したいVCのハッシュ)
  - proof (MerkleProof)
  - merkleRoot (期待される根)

Output: Bool (検証成功/失敗)

Algorithm:
  1. 葉から開始
     currentHash = vcHash
     currentIndex = proof.leafIndex

  2. 根まで計算
     for siblingHash in proof.siblingHashes:
       if currentIndex % 2 == 0:
         // 左の子
         currentHash = SHA-256(currentHash || siblingHash)
       else:
         // 右の子
         currentHash = SHA-256(siblingHash || currentHash)

       currentIndex = currentIndex / 2

  3. 根と比較
     return currentHash == merkleRoot
```

---

## 4. ZKP Circuit Integration

### 4.1 ZKP回路の制約

```
Public Input:
  - revocation_enabled (失効確認の有効化フラグ、VCのクレーム内に含まれる)
  - merkle_root (最新のMerkle Root、revocation_enabled = true の場合のみ)
  - merkle_root_version (バージョン番号、revocation_enabled = true の場合のみ)
  - claimed_attributes (age >= 20, etc.)
  - verifier_nonce
  - holder_nonce

Private Input:
  - vc_full (VC全体の内容)
  - issuer_signature (IssuerのVC署名)
  - merkle_proof.leafIndex (revocation_enabled = true の場合のみ)
  - merkle_proof.siblingHashes (revocation_enabled = true の場合のみ)
  - merkle_proof.treeDepth (revocation_enabled = true の場合のみ)

Constraints:
  1. Issuer署名検証
     Verify(issuer_signature, vc_full, issuer_pubkey) = true

  2. VCからrevocationEnabledフラグを抽出
     extracted_revocation_enabled = ExtractRevocationEnabled(vc_full)
     assert extracted_revocation_enabled == revocation_enabled
     // ✅ HolderがrevocationEnabledフラグを偽造不可能
     //    VCのクレームに含まれるrevocationEnabledとPublic Inputが一致

  3. VCハッシュ計算
     vc_hash = SHA-256(Canonicalize(vc_full))

  4. Merkle証明検証（revocation_enabled = true の場合のみ）
     if revocation_enabled == true:
       current = vc_hash
       index = merkle_proof.leafIndex

       for sibling in merkle_proof.siblingHashes:
         if index % 2 == 0:
           current = SHA-256(current || sibling)
         else:
           current = SHA-256(sibling || current)
         index = index / 2

       assert current == merkle_root
       // ✅ VCがActive Listに含まれている = 失効していない
     else:
       // revocation_enabled == false の場合、Merkle証明検証をスキップ
       // ⚠️ Verifierは失効確認が行われていないことを認識可能

  5. 属性の選択的開示
     extracted = ExtractAttributes(vc_full, claimed_attributes)
     assert extracted satisfies claimed_attributes
     // 例: vc_full.age >= 20 and claimed_attributes.age_over_20 = true

  6. 双方向ナンス検証
     nonce_combined = SHA-256(holder_nonce || verifier_nonce)
     assert nonce_combined is_bound_to_proof
     // リプレイ攻撃防止

// Note: タイムスタンプ検証は削除
//       Holderが制御可能なタイムスタンプをZKP回路内で検証しても
//       暗号理論的に安全でない。Verifier側でIssuer署名付きの
//       validUntilを検証することで、安全性を保証する。

// Note: revocationEnabledフラグの検証の重要性
//       Constraint 2により、HolderがrevocationEnabledフラグを偽造できない
//       VCのクレーム内に含まれるrevocationEnabledはIssuer署名で保護されている
//       ゆえに、Verifierは数学的に失効確認の有無を判定可能
```

### 4.2 ZKP生成の流れ

#### 4.2.1 失効確認有効（revocationEnabled = true）の場合

```
1. 事前計算フェーズ（オフライン、数分〜数時間）
   - VC署名検証の事前計算
   - 属性抽出の回路評価
   - 部分的な証明生成

2. Merkle Root取得（リアルタイム、数秒）
   Holder → GET /api/merkle-root → Issuer
   Response: {
     merkleRoot: "0x...",
     version: 12345,
     validUntil: "2025-10-13T15:00:00Z",
     issuerSignature: "..."
   }

3. Merkle証明生成（リアルタイム、数ミリ秒）
   vcHash = SHA-256(vc_full)
   merkleProof = GenerateMerkleProof(vcHash, activeVCHashes)

4. 双方向ナンス結合（リアルタイム、数ミリ秒）
   Holder ← verifier_nonce ← Verifier
   holder_nonce = RandomBytes(16)
   nonce_combined = SHA-256(holder_nonce || verifier_nonce)

5. 最終ZKP生成（リアルタイム、数百ミリ秒）
   zkp = Combine(
     precomputed_proof,
     merkle_proof,
     nonce_combined
   )

6. 送信
   Holder → (zkp, revocation_enabled=true, merkle_root, merkle_root_version, holder_nonce) → Verifier
```

#### 4.2.2 失効確認無効（revocationEnabled = false）の場合

```
1. 事前計算フェーズ（オフライン、数分〜数時間）
   - VC署名検証の事前計算
   - 属性抽出の回路評価
   - 部分的な証明生成

2. Merkle Root取得（スキップ）
   // ⚠️ revocationEnabled = false のため不要

3. Merkle証明生成（スキップ）
   // ⚠️ revocationEnabled = false のため不要

4. 双方向ナンス結合（リアルタイム、数ミリ秒）
   Holder ← verifier_nonce ← Verifier
   holder_nonce = RandomBytes(16)
   nonce_combined = SHA-256(holder_nonce || verifier_nonce)

5. 最終ZKP生成（リアルタイム、数百ミリ秒）
   zkp = Combine(
     precomputed_proof,
     nonce_combined
   )
   // Merkle証明は含まれない

6. 送信
   Holder → (zkp, revocation_enabled=false, holder_nonce) → Verifier
   // merkle_root, merkle_root_versionは送信しない
```

---

## 5. Issuer Operations

### 5.1 VC発行

#### 5.1.1 失効確認有効（revocationEnabled = true）の場合

組織Issuerや、ウェブサーバーを管理できるIssuer向け：

```
1. VCを生成（revocationEnabledフラグを含める）
   vc = CreateVC(
     subject,
     claims: {
       ...user_claims,
       revocationEnabled: true  // ⚠️ 必須フラグ
     },
     issuer_signature
   )

2. VCハッシュを計算
   vc_hash = SHA-256(Canonicalize(vc))

3. Active Listに追加
   activeVCHashes.append(vc_hash)

4. Merkle Root更新
   merkleRoot = BuildMerkleTree(activeVCHashes)

5. 署名付きMerkle Rootを公開
   merkleRevocationList = {
     activeVCHashes,
     merkleRoot,
     updatedAt: now(),
     validUntil: now() + 1h,
     version: current_version + 1,
     issuerSignature: Sign(merkleRoot || version || validUntil)
   }

6. VCとMerkle証明をHolderに送信
   merkleProof = GenerateMerkleProof(vc_hash, activeVCHashes)

   Send to Holder: {
     vc,  // revocationEnabled: true を含む
     merkleProof,
     merkleRoot,
     version
   }
```

#### 5.1.2 失効確認無効（revocationEnabled = false）の場合

個人Issuerや、ウェブサーバーを管理できないIssuer向け：

```
1. VCを生成（revocationEnabledフラグをfalseに設定）
   vc = CreateVC(
     subject,
     claims: {
       ...user_claims,
       revocationEnabled: false  // ⚠️ 失効確認なし
     },
     issuer_signature
   )

2. VCハッシュを計算（不要だがオプション）
   // Active Listへの追加は不要

3. Active Listへの追加（スキップ）
   // ⚠️ revocationEnabled = false のため不要

4. Merkle Root更新（スキップ）
   // ⚠️ revocationEnabled = false のため不要

5. 署名付きMerkle Root公開（スキップ）
   // ⚠️ revocationEnabled = false のため不要

6. VCのみをHolderに送信
   Send to Holder: {
     vc  // revocationEnabled: false を含む
   }
   // Merkle証明、Merkle Rootは送信しない
```

### 5.2 VC失効

#### 5.2.1 失効確認有効（revocationEnabled = true）のVCの失効

```
1. Holderから失効リクエスト受信
   Request: { vc_id, reason, holder_signature }

2. VCハッシュを計算
   vc_hash = SHA-256(Canonicalize(vc))

3. Active Listから削除
   activeVCHashes.remove(vc_hash)

4. 新しいMerkle Root生成
   newMerkleRoot = BuildMerkleTree(activeVCHashes)

5. 署名付きで公開
   merkleRevocationList = {
     activeVCHashes,
     merkleRoot: newMerkleRoot,
     updatedAt: now(),
     validUntil: now() + 1h,
     version: current_version + 1,
     issuerSignature: Sign(newMerkleRoot || version || validUntil)
   }

6. 失効ログを記録（監査用）
   revocationLog.append({
     vc_id,
     vc_hash,
     revoked_at: now(),
     reason
   })
```

#### 5.2.2 失効確認無効（revocationEnabled = false）のVCの失効

```
失効確認無効のVCは、そもそも失効メカニズムが存在しない：

⚠️ 設計上の制約:
  - revocationEnabled = false のVCはActive Listに含まれていない
  - Issuerが失効を実行する手段がない
  - HolderがVCを破棄する以外に失効方法がない

代替手段:
  1. Holderに対して「VCを破棄してください」と通知
  2. 新しいVCを発行し直す（今度はrevocationEnabled = true）
  3. Verifier側のポリシーで「revocationEnabled = false」を拒否

注意:
  個人IssuerがrevocationEnabled = false のVCを発行する際は、
  「失効不可能」であることをHolder/Verifierに明示すべき
```

### 5.3 定期的なMerkle Root更新

```
// 1時間ごとに実行（Cron Job）
function UpdateMerkleRoot():
  1. 現在のActive Listを読み込み
     activeVCHashes = LoadActiveList()

  2. Merkle Root再計算
     merkleRoot = BuildMerkleTree(activeVCHashes)

  3. バージョン番号をインクリメント
     version = current_version + 1

  4. 有効期限を設定
     validUntil = now() + 1h

  5. 署名
     issuerSignature = Sign(merkleRoot || version || validUntil)

  6. 公開
     PublishMerkleRoot({
       merkleRoot,
       version,
       updatedAt: now(),
       validUntil,
       issuerSignature
     })
```

### 5.4 API Endpoints

```
GET /api/merkle-root
  Response: {
    "merkleRoot": "0x1234...",
    "version": 12345,
    "updatedAt": "2025-10-13T14:00:00Z",
    "validUntil": "2025-10-13T15:00:00Z",
    "issuerSignature": "0xabcd..."
  }

GET /api/merkle-proof?vc_id={vc_id}
  Response: {
    "vcHash": "0x5678...",
    "leafIndex": 42,
    "siblingHashes": ["0x...", "0x...", ...],
    "treeDepth": 10,
    "merkleRoot": "0x1234...",
    "version": 12345
  }

POST /api/revoke
  Request: {
    "vc_id": "urn:uuid:...",
    "reason": "引っ越しによる住所変更",
    "holder_signature": "0x..."
  }
  Response: {
    "success": true,
    "newMerkleRoot": "0x9abc...",
    "newVersion": 12346
  }
```

---

## 6. Holder Operations

### 6.1 ZKP生成（失効確認付き）

```
Input:
  - vc (保持しているVC)
  - merkleProof (Issuerから取得済み、またはActive Listから自己生成、revocationEnabled = true の場合のみ)
  - publicAttributes (公開したい属性)
  - verifierNonce (Verifierから受信)

Output: ZKP

Function GenerateZKPWithRevocation(vc, merkleProof, publicAttributes, verifierNonce):
  // VCからrevocationEnabledフラグを抽出
  revocationEnabled = ExtractRevocationEnabled(vc)

  if revocationEnabled == true:
    // 失効確認有効の場合

    1. 最新のMerkle Rootを取得
       merkleRootData = HTTP_GET(issuer.merkle_root_endpoint)

       // Issuer署名を検証
       if !VerifySignature(merkleRootData, issuer.pubkey):
         return Error("Invalid Merkle Root signature")

       // 有効期限を確認
       if now() > merkleRootData.validUntil:
         return Error("Merkle Root expired")

    2. Merkle証明を検証（ローカル）
       vcHash = SHA-256(Canonicalize(vc))
       if !VerifyMerkleProof(vcHash, merkleProof, merkleRootData.merkleRoot):
         return Error("VC is revoked or proof is invalid")

    3. Holderナンスを生成
       holderNonce = RandomBytes(16)

    4. ZKP秘密入力を準備
       secretInputs = {
         vcContent: vc,
         issuerSignature: vc.proof.proofValue,
         merkleProof: Some(merkleProof),
         additionalSecrets: {...}
       }

    5. ZKP公開入力を準備
       publicInputs = {
         revocationEnabled: true,
         merkleRoot: Some(merkleRootData.merkleRoot),
         merkleRootVersion: Some(merkleRootData.version),
         publicAttributes: publicAttributes,
         verifierNonce: verifierNonce,
         holderNonce: holderNonce
       }

    6. ZKPを生成
       zkp = GenerateZKP(
         circuit: RevocationCircuit,
         secretInputs: secretInputs,
         publicInputs: publicInputs
       )

    7. 返却
       return {
         zkp,
         revocationEnabled: true,
         merkleRoot: merkleRootData.merkleRoot,
         merkleRootVersion: merkleRootData.version,
         holderNonce
       }

  else:
    // 失効確認無効の場合

    1. Merkle Root取得（スキップ）
       // ⚠️ revocationEnabled = false のため不要

    2. Merkle証明検証（スキップ）
       // ⚠️ revocationEnabled = false のため不要

    3. Holderナンスを生成
       holderNonce = RandomBytes(16)

    4. ZKP秘密入力を準備
       secretInputs = {
         vcContent: vc,
         issuerSignature: vc.proof.proofValue,
         merkleProof: None,  // Merkle証明なし
         additionalSecrets: {...}
       }

    5. ZKP公開入力を準備
       publicInputs = {
         revocationEnabled: false,
         merkleRoot: None,
         merkleRootVersion: None,
         publicAttributes: publicAttributes,
         verifierNonce: verifierNonce,
         holderNonce: holderNonce
       }

    6. ZKPを生成
       zkp = GenerateZKP(
         circuit: RevocationCircuit,
         secretInputs: secretInputs,
         publicInputs: publicInputs
       )

    7. 返却
       return {
         zkp,
         revocationEnabled: false,
         holderNonce
       }
       // merkleRoot, merkleRootVersionは含まれない
```

### 6.2 Merkle証明の自己生成

Holderが全Active Listを保持している場合（オプション）：

```
Function SelfGenerateMerkleProof(vc, activeVCHashes):
  1. VCハッシュを計算
     vcHash = SHA-256(Canonicalize(vc))

  2. Active List内で位置を特定
     leafIndex = activeVCHashes.indexOf(vcHash)
     if leafIndex == -1:
       return Error("VC is revoked")

  3. Merkle証明を生成
     merkleProof = GenerateMerkleProof(vcHash, activeVCHashes)

  4. 返却
     return merkleProof
```

---

## 7. Verifier Operations

### 7.1 ZKP検証（失効確認付き）

```
Input:
  - zkp (Holderから受信)
  - revocationEnabled (HolderがZKP生成時に使用したフラグ、ZKP公開入力に含まれる)
  - merkleRoot (HolderがZKP生成時に使用したもの、revocationEnabled = true の場合のみ)
  - merkleRootVersion (revocationEnabled = true の場合のみ)
  - holderNonce
  - verifierNonce (自分が送信したもの)
  - publicAttributes (期待する属性)

Output: Bool (検証成功/失敗)

Function VerifyZKPWithRevocation(zkp, revocationEnabled, merkleRoot, merkleRootVersion, holderNonce, verifierNonce, publicAttributes):
  // ⚠️ 重要: revocationEnabledフラグの検証
  //    このフラグはZKP公開入力に含まれており、ZKP回路内で検証済み
  //    HolderがフラグをVCから抽出し、ZKP回路のConstraint 2で検証される
  //    ゆえに、revocationEnabledフラグは数学的に信頼できる

  if revocationEnabled == true:
    // 失効確認有効の場合

    1. Merkle Rootの検証
       // Issuerから最新のMerkle Rootを取得
       latestMerkleRootData = HTTP_GET(issuer.merkle_root_endpoint)

       // Issuer署名を検証
       if !VerifySignature(latestMerkleRootData, issuer.pubkey):
         return False  // Issuer署名が不正

       // HolderがZKP生成時に使用したMerkle Rootを取得
       merkleRootUsedByHolder = GetHistoricalMerkleRoot(merkleRootVersion)
       if merkleRootUsedByHolder == None:
         return False  // 無効なバージョン

       // Issuer署名を検証（過去のMerkle Rootも署名されている）
       if !VerifySignature(merkleRootUsedByHolder, issuer.pubkey):
         return False  // Issuer署名が不正

    2. タイムスタンプ検証（Verifier側で実行）
       // ⭐ 重要: Issuer署名付きのvalidUntilを検証
       //   Holderが偽造できない（Issuer秘密鍵が必要）
       if now() > merkleRootUsedByHolder.validUntil:
         return False  // Merkle Rootの有効期限切れ

       // バージョン確認（タイムラグ許容）
       // 例: MAX_VERSION_LAG = 5 (5時間分のタイムラグを許容)
       if latestMerkleRootData.version - merkleRootVersion > MAX_VERSION_LAG:
         return False  // Merkle Rootが古すぎる

       // Merkle Rootの一致確認
       if merkleRoot != merkleRootUsedByHolder.merkleRoot:
         return False  // Merkle Root不一致

    3. ZKP検証
       publicInputs = {
         revocationEnabled: true,
         merkleRoot: Some(merkleRoot),
         merkleRootVersion: Some(merkleRootVersion),
         publicAttributes,
         verifierNonce,
         holderNonce
       }

       if !VerifyZKP(zkp, publicInputs):
         return False  // ZKP検証失敗

    4. ナンス検証
       if verifierNonce != my_sent_nonce:
         return False  // リプレイ攻撃

       // ナンスの一意性を記録（二重使用防止）
       if IsNonceUsed(holderNonce, verifierNonce):
         return False
       RecordNonce(holderNonce, verifierNonce)

    5. 成功
       return True

  else:
    // 失効確認無効の場合

    1. Verifierポリシーの確認
       // ⚠️ Verifierは失効確認が行われていないことを認識
       //    revocationEnabled = false のVCを受け入れるかどうかは、
       //    Verifierのポリシー次第

       if !AcceptNonRevocableVC():
         return False  // 失効確認なしのVCを拒否

    2. ZKP検証（失効確認なし）
       publicInputs = {
         revocationEnabled: false,
         merkleRoot: None,
         merkleRootVersion: None,
         publicAttributes,
         verifierNonce,
         holderNonce
       }

       if !VerifyZKP(zkp, publicInputs):
         return False  // ZKP検証失敗

    3. ナンス検証
       if verifierNonce != my_sent_nonce:
         return False  // リプレイ攻撃

       // ナンスの一意性を記録（二重使用防止）
       if IsNonceUsed(holderNonce, verifierNonce):
         return False
       RecordNonce(holderNonce, verifierNonce)

    4. 成功（失効確認なし）
       LogWarning("Revocation check skipped: revocationEnabled = false")
       return True
```

### 7.2 オフライン検証モード（災害時）

```
Function VerifyZKPOffline(zkp, merkleRoot, publicAttributes):
  // Merkle Root取得をスキップ
  // （災害時、Issuerのサーバーにアクセスできない場合）

  1. 事前にキャッシュされたIssuer公開鍵で署名検証
     cachedIssuerPubkey = LoadCachedIssuerPubkey()

     // ZKP内のIssuer署名を検証（Merkle証明は含まない）
     if !VerifyZKPWithoutRevocation(zkp, cachedIssuerPubkey, publicAttributes):
       return False

  2. 警告を記録
     LogWarning("Offline mode: Revocation check skipped")

  3. 成功（失効確認なし）
     return True
```

---

## 8. W3C VC Integration

### 8.1 credentialStatus拡張

W3C VCの`credentialStatus`フィールドを拡張します。

#### 8.1.1 失効確認有効（revocationEnabled = true）の場合

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://amatelus.example/context/revocation/v1"
  ],
  "id": "urn:uuid:12345678-1234-1234-1234-123456789abc",
  "type": ["VerifiableCredential", "ResidentRegistrationCredential"],
  "issuer": "did:amatelus:abc123...",
  "issuanceDate": "2025-10-13T00:00:00Z",
  "credentialSubject": {
    "id": "did:amatelus:xyz789...",
    "name": "山田太郎",
    "address": "東京都...",
    "revocationEnabled": true
  },
  "credentialStatus": {
    "id": "https://issuer.example/status/merkle/v1",
    "type": "MerkleTreeRevocationList2024",
    "merkleRootEndpoint": "https://issuer.example/api/merkle-root",
    "merkleProofEndpoint": "https://issuer.example/api/merkle-proof",
    "vcHash": "0x1234567890abcdef..."
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amatelus:abc123...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FkdP4..."
  }
}
```

#### 8.1.2 失効確認無効（revocationEnabled = false）の場合

個人Issuer向け：

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://amatelus.example/context/revocation/v1"
  ],
  "id": "urn:uuid:87654321-4321-4321-4321-cba987654321",
  "type": ["VerifiableCredential", "PersonalRecommendationCredential"],
  "issuer": "did:amatelus:individual456...",
  "issuanceDate": "2025-10-13T00:00:00Z",
  "credentialSubject": {
    "id": "did:amatelus:xyz789...",
    "name": "山田太郎",
    "recommendation": "優れたエンジニア",
    "revocationEnabled": false
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amatelus:individual456...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FkdP4..."
  }
}
```

**注意点**:
- `revocationEnabled = false`の場合、`credentialStatus`フィールドは省略
- `credentialSubject`内に`revocationEnabled: false`を含める（Issuer署名で保護）
- Verifierはこのフラグを確認し、失効確認なしのVCを受け入れるかどうかポリシー判定

### 8.2 Merkle証明の添付（オプション）

Holderは、VCと一緒にMerkle証明を保持できます：

```json
{
  "vc": { ... },
  "merkleProof": {
    "type": "MerkleProof2024",
    "leafIndex": 42,
    "siblingHashes": [
      "0x1234...",
      "0x5678...",
      "0x9abc..."
    ],
    "treeDepth": 10,
    "merkleRoot": "0xdef0...",
    "merkleRootVersion": 12345,
    "createdAt": "2025-10-13T14:00:00Z"
  }
}
```

---

## 9. Security Analysis

### 9.1 ゼロ知識性の保証

| 方式 | どのVCか特定可能？ | 開示される情報 | ゼロ知識性 |
|------|-------------------|----------------|-----------|
| Bitstring Status List | **Yes** | `statusListIndex` | ❌ |
| Merkle Tree方式 | **No** | `merkleRoot`のみ | ✅ |

**証明**:
- Verifierは`merkleRoot`のみを受け取る
- `merkleRoot`は全アクティブVCのハッシュから生成される
- 特定のVCを識別する情報は含まれない
- ZKP回路内でMerkle証明を検証するため、証明パスも秘匿される

### 9.2 失効確認の安全性（Lean 4で形式検証済み）

以下の定理は、Lean 4による形式検証により**数学的に証明**されています（`AMATELUS/RevocationMerkle.lean`参照）。

**Theorem 9.2.1 (正しいMerkle証明は常に検証成功)**:
```lean
theorem valid_merkle_proof_passes :
  ∀ (vmp : ValidMerkleProof),
    UnknownMerkleProof.isValid (UnknownMerkleProof.valid vmp)
```

**Theorem 9.2.2 (不正なMerkle証明は常に検証失敗)**:
```lean
theorem invalid_merkle_proof_fails :
  ∀ (imp : InvalidMerkleProof),
    ¬UnknownMerkleProof.isValid (UnknownMerkleProof.invalid imp)
```

**Theorem 9.2.3 (失効VCでZKP生成不可能)** ✅:
```lean
theorem revoked_vc_cannot_generate_zkp :
  ∀ (secretInputs : ZKPSecretInputWithRevocation)
    (publicInputs : ZKPPublicInputWithRevocation),
  secretInputs.merkleProof.verify = false →
  ∃ (izkp : InvalidZKP),
    generateZKPWithRevocation secretInputs publicInputs =
      UnknownZKP.invalid izkp
```

**証明の要点**:
1. VCが失効される → `activeVCHashes`から`vc_hash`が削除される
2. 新しい`merkleRoot`が生成される（`vc_hash`を含まない）
3. Holderが失効VCでZKP生成を試みる
4. Merkle証明検証が失敗 (`verify = false`) → ZKP生成が失敗 (`UnknownZKP.invalid`)
5. 形式検証により、この因果関係が**数学的に保証**される

**Theorem 9.2.4 (有効なMerkle証明から有効なZKP生成)** ✅:
```lean
theorem valid_merkle_proof_generates_valid_zkp :
  ∀ (secretInputs : ZKPSecretInputWithRevocation)
    (publicInputs : ZKPPublicInputWithRevocation),
  secretInputs.merkleProof.verify = true →
  secretInputs.merkleProof.getRoot = publicInputs.merkleRoot →
  ∃ (vzkp : ValidZKP),
    generateZKPWithRevocation secretInputs publicInputs =
      UnknownZKP.valid vzkp
```

この定理により、失効していないVCで**必ずZKPを生成できる**ことが保証されます（完全性）。

### 9.3 リプレイ攻撃耐性

**双方向ナンス機構**:
```
nonce_combined = SHA-256(holder_nonce || verifier_nonce)
```

- **Holderのバグ**: `holder_nonce`が固定でも、`verifier_nonce`のランダム性で保護
- **Verifierのバグ**: `verifier_nonce`が固定でも、`holder_nonce`のランダム性で保護
- **リプレイ攻撃**: 過去のZKPを再送信しても、`verifier_nonce`が異なるため拒否される

### 9.4 タイムスタンプ検証の安全性

**問題**: ZKP回路内でタイムスタンプを検証すると、Holderが偽造可能

```
❌ 安全でない設計:
  Private Input: current_time (Holderが制御可能)
  Constraint: current_time <= merkle_root_valid_until

  攻撃:
    Holder: current_time = 過去の時刻に設定
    → 古いMerkle Root（失効前）を使用可能
```

**解決策**: Verifier側でIssuer署名付きvalidUntilを検証

```
✅ 安全な設計:
  1. Issuerが署名
     issuerSignature = Sign(merkleRoot || version || validUntil)

  2. Verifierが検証
     Verify(issuerSignature, issuer.pubkey) = True
     now() <= validUntil

  保証:
    - Holderが偽造不可能（Issuer秘密鍵が必要）
    - Issuer署名により完全性保証
    - Verifierの現在時刻で判定（信頼できる）
```

**Theorem 9.2 (タイムスタンプ偽造不可能性)**:
```
∀ Holder (攻撃者),
  issuerSignature = Sign(merkleRoot || version || validUntil, issuer_privkey)

  Holderが validUntil を改ざんするには:
    1. Issuer秘密鍵の取得（計算量的に困難）
    2. または、署名偽造（Dilithium2で2^128の計算量）

  ⟹ タイムスタンプ偽造は計算量的に困難
```

**タイムラグ許容の設計**:
```
MAX_VERSION_LAG = 5 (例: 5時間分)

Timeline:
  14:00 - Version 100 (validUntil: 15:00)
  15:00 - Version 101 (validUntil: 16:00)
  ...
  19:00 - Version 105 (validUntil: 20:00) ← 最新

Holder (19:30):
  Version 100でZKP生成を試みる

Verifier (19:30):
  ✅ Version差分: 105 - 100 = 5 → 許容範囲内
  ❌ validUntil: 15:00 < 19:30 → 期限切れ → 拒否

  → 失効済みVCの悪用を防止
```

### 9.6 計算量

| 操作 | 計算量 | 例（N = 1,000,000） |
|------|--------|---------------------|
| Merkle Tree構築 | O(N) | 1,000,000回ハッシュ |
| Merkle証明生成 | O(log N) | 20回ハッシュ |
| Merkle証明検証 | O(log N) | 20回ハッシュ |
| ZKP回路内検証 | O(log N) | 20回SHA-256 |

**スケーラビリティ**:
- 1億枚のアクティブVC → Merkle証明の深さ = 27
- ZKP回路内で27回のSHA-256計算 → 実用的

### 9.7 Merkle Rootの改ざん耐性

**Issuer署名の検証**:
```
issuerSignature = Sign(merkleRoot || version || validUntil, issuer_privkey)
Verify(issuerSignature, issuer_pubkey) = True
```

- Merkle Rootの改ざん → 署名検証失敗
- 第三者が偽のMerkle Rootを公開 → Issuer公開鍵で検証できない
- 量子安全性: Dilithium2等のPQC署名を使用

---

## 10. Performance Considerations

### 10.1 Issuer側の負荷

```
1. VC発行時
   - Merkle Tree再構築: O(N)
   - 署名生成: O(1)
   - 合計: O(N)

   対策: バッチ発行（1時間に1回まとめて更新）

2. VC失効時
   - Merkle Tree再構築: O(N)
   - 署名生成: O(1)
   - 合計: O(N)

   対策: 失効キューに追加し、定期更新時に一括処理

3. 定期更新
   - 頻度: 1時間ごと
   - 処理時間: N = 1,000,000で約1秒（SHA-256 x 2N回）
```

### 10.2 Holder側の負荷

```
1. ZKP生成（事前計算フェーズ）
   - VC署名検証: 事前計算可能
   - 属性抽出: 事前計算可能
   - 時間: 数分〜数時間（オフライン）

2. ZKP生成（リアルタイムフェーズ）
   - Merkle Root取得: HTTP GET（数ミリ秒）
   - Merkle証明生成: O(log N)（数ミリ秒）
   - 双方向ナンス結合: O(1)（数ミリ秒）
   - 最終ZKP生成: O(log N)（数百ミリ秒）
   - 合計: 約1秒以内
```

### 10.3 Verifier側の負荷

```
1. Merkle Root検証
   - HTTP GET: 数ミリ秒
   - Issuer署名検証: O(1)（数ミリ秒）

2. ZKP検証
   - Groth16検証: O(1)（数十ミリ秒）

3. 合計
   - 約100ミリ秒以内
```

### 10.4 最適化手法

```
1. Merkle Treeのキャッシュ
   - 部分木をキャッシュ → 差分更新でO(log N)

2. Active Listの圧縮
   - Bloom FilterでO(1)チェック（誤検知あり）
   - Merkle Treeで最終確認（誤検知なし）

3. 並列計算
   - Merkle Tree構築をマルチスレッド化
   - GPU活用（SHA-256は並列化容易）

4. 複数バージョンの保持
   - 最新5バージョンを保持
   - Holderがわずかにタイムラグしても検証可能
```

---

## 11. Comparison with Other Revocation Mechanisms

| 方式 | ゼロ知識性 | 計算量 | オフライン可能 | W3C互換 |
|------|-----------|-------|---------------|---------|
| Bitstring Status List | ❌ | O(1) | ❌ | ✅ |
| CRL (Certificate Revocation List) | ❌ | O(N) | ❌ | ❌ |
| OCSP (Online Certificate Status Protocol) | ❌ | O(1) | ❌ | ❌ |
| Accumulator | ✅ | O(1) | ❌ | ❌ |
| **Merkle Tree (AMATELUS)** | **✅** | **O(log N)** | **✅** | **✅** |

### 11.1 Accumulatorとの比較

**Cryptographic Accumulator**の利点:
- 証明サイズ: O(1)
- 検証時間: O(1)

**Merkle Treeの利点**:
- 実装の単純性（SHA-256のみ）
- ZKP回路との互換性（SHA-256はGroth16で効率的）
- 量子安全性（ハッシュベース）

**AMATELUSの選択理由**:
- SHA-256は既にZKP回路で広く使用されている
- Accumulatorは複雑な数学（RSA, Pairing）が必要
- 量子コンピュータへの耐性（SHA-256は量子安全）

---

## 12. Implementation Guidelines

### 12.1 Issuer実装チェックリスト

- [ ] Active VCリストのデータベース設計
- [ ] Merkle Tree構築ライブラリ（SHA-256）
- [ ] 定期更新Cron Job（1時間ごと）
- [ ] API Endpoints実装
  - [ ] `GET /api/merkle-root`
  - [ ] `GET /api/merkle-proof`
  - [ ] `POST /api/revoke`
- [ ] Issuer署名鍵の管理（HSM推奨）
- [ ] 失効ログの監査記録
- [ ] 複数バージョンのMerkle Root保持（最新5個）

### 12.2 Holder実装チェックリスト

- [ ] Merkle Root取得ロジック
- [ ] Merkle証明生成/検証ロジック
- [ ] ZKP回路統合
  - [ ] SHA-256回路（Merkle検証用）
  - [ ] Issuer署名検証回路
  - [ ] 属性抽出回路
- [ ] 事前計算管理（バックグラウンドタスク）
- [ ] オフラインモード対応
- [ ] エラーハンドリング（失効時の通知）

### 12.3 Verifier実装チェックリスト

- [ ] Issuer公開鍵の取得と検証
- [ ] Merkle Root取得と署名検証
- [ ] ZKP検証ライブラリ
- [ ] ナンス管理（二重使用防止）
- [ ] タイムスタンプ検証
- [ ] オフラインモード対応（オプション）
- [ ] ログ記録（監査用）

### 12.4 テストケース

```
1. 正常系
   - アクティブVCでZKP生成 → 成功
   - ZKP検証 → 成功

2. 失効検出
   - VCを失効
   - 失効VCでZKP生成 → 失敗（Merkle証明生成不可）

3. 古いMerkle Root（期限切れ）
   - 1時間前のMerkle RootでZKP生成
   - Verifier検証 → 失敗（validUntil期限切れ）

4. 古いMerkle Root（バージョン差が大きい）
   - 10バージョン前のMerkle RootでZKP生成
   - Verifier検証 → 失敗（MAX_VERSION_LAG超過）

5. タイムスタンプ偽造攻撃
   - Holder: 古いMerkle Root + 過去のタイムスタンプでZKP生成を試みる
   - Verifier: Issuer署名付きvalidUntilを検証
   - Verifier検証 → 失敗（validUntil期限切れ）
   - ✅ Holderがタイムスタンプを偽造できないことを確認

6. リプレイ攻撃
   - 同じZKPを2回送信
   - 2回目の検証 → 失敗（ナンス重複）

7. Merkle Root改ざん攻撃
   - Merkle Rootを改ざん
   - Issuer署名検証 → 失敗

8. validUntil改ざん攻撃
   - validUntilを改ざん
   - Issuer署名検証 → 失敗
   - ✅ Issuer署名により完全性保証

9. オフラインモード
   - Issuerサーバーダウン
   - オフライン検証 → 成功（警告あり）
```

---

## 13. Migration Path from Bitstring Status List

既存のBitstring Status Listを使用しているシステムからの移行手順：

### 13.1 フェーズ1: 並行運用

```
1. 新規VCにMerkleTreeRevocationList2024を追加
   credentialStatus: {
     type: ["BitstringStatusListEntry", "MerkleTreeRevocationList2024"],
     ...
   }

2. Issuerが両方式をサポート
   - Bitstring Status List更新
   - Merkle Root更新

3. Verifierが両方式をサポート
   - ZKPでMerkle Tree検証
   - 従来方式でBitstring確認（ZKPなし）
```

### 13.2 フェーズ2: 段階的移行

```
1. 新規発行VCはMerkle Tree方式のみ

2. 既存VCの再発行促進
   - 「引っ越し」「更新」等のタイミングで移行

3. Bitstring Status List廃止予定を告知
```

### 13.3 フェーズ3: 完全移行

```
1. Bitstring Status List APIを停止

2. 既存VCの強制失効
   - 十分な移行期間後（例: 1年後）

3. Merkle Tree方式のみに統一
```

---

## 14. Future Extensions

### 14.1 Sparse Merkle Tree

現在の仕様はBinary Merkle Treeですが、Sparse Merkle Treeに拡張可能：

- **メリット**: VC IDから直接位置を計算（leafIndex不要）
- **デメリット**: ツリーサイズが固定（2^256等）

### 14.2 Batched Revocation

複数VCの一括失効：

```
BatchRevocation = {
  vc_hashes: [h₁, h₂, ..., hₙ],
  reason: "大量流出による一括失効",
  issuer_signature: ...
}
```

### 14.3 Conditional Revocation

条件付き失効（スマートコントラクト連携）：

```
ConditionalRevocation = {
  vc_hash: h,
  condition: "if block.timestamp > expiry_date",
  proof: ZK-Proof
}
```

### 14.4 Cross-Issuer Revocation Federation

複数Issuer間でMerkle Rootを共有：

```
FederatedMerkleRoot = MerkleRoot([
  issuer1.merkleRoot,
  issuer2.merkleRoot,
  ...
])
```

---

## 15. Conclusion

本仕様により、AMATELUSプロトコルは以下を実現します：

1. **ゼロ知識性の保持**: W3C Bitstring Status Listの欠点を克服
2. **失効確認の安全性**: 失効されたVCでZKP生成が不可能
3. **タイムスタンプ偽造耐性**: Issuer署名付きvalidUntilにより、Holderがタイムスタンプを偽造不可能
4. **スケーラビリティ**: O(log N)の計算量で大規模運用可能
5. **災害時の可用性**: オフライン時は失効確認スキップ可能
6. **W3C VC互換**: credentialStatus拡張として標準準拠
7. **個人Issuerの対応**: revocationEnabledフラグにより、ウェブサーバーなしでVC発行可能

### 暗号理論的な安全性保証

本仕様は、以下の暗号理論的な安全性を保証します：

| 攻撃 | 防御メカニズム | 安全性根拠 |
|------|---------------|-----------|
| 失効VCの悪用 | Merkle証明検証（ZKP回路内） | 計算量的に困難 |
| タイムスタンプ偽造 | Issuer署名付きvalidUntil検証（Verifier側） | Dilithium2署名偽造: 2^128 |
| Merkle Root改ざん | Issuer署名検証 | Dilithium2署名偽造: 2^128 |
| リプレイ攻撃 | 双方向ナンス機構 | ナンスの一意性 |

### 設計の核心

#### revocationEnabledフラグの重要性

従来設計の問題点：
- Holderが失効確認結果をZKPに含めなかった場合、Verifierはそもそも失効確認可能なVCかどうかを知ることができない
- これにより、失効確認をスキップされても検出不可能

本仕様の解決策：
1. **Issuerがクレームごとに失効確認の可否を含める**（`revocationEnabled`フラグ）
2. **HolderはZKPに失効確認フラグを入力**（ZKP公開入力に含まれる）
3. **Verifierは数学的に失効確認の有無を判定可能**（ZKP回路のConstraint 2で検証）
4. **個人Issuerはサーバー管理不要**（`revocationEnabled = false`のVCを発行可能）

#### タイムスタンプ偽造耐性

ZKP回路内でタイムスタンプを検証しない理由：
- Holderが制御可能な情報（現在時刻）をZKP回路内で検証しても、暗号理論的に安全でない
- Verifier側でIssuer署名付きvalidUntilを検証することで、Holderがタイムスタンプを偽造できない
- これにより、古いMerkle Root（失効前）を使用した攻撃を防止

この設計は、プライバシー保護と失効確認の両立という、ZKPベースのVerifiable Credentials運用における根本的課題を解決します。

---

## References

1. [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
2. [W3C Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)
3. [Merkle Tree - Wikipedia](https://en.wikipedia.org/wiki/Merkle_tree)
4. [RFC 6962: Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
5. [Groth16: On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)
6. [ZK-SNARKs for Merkle Tree Verification](https://github.com/iden3/circomlib)
7. [AMATELUS Protocol Specification](../README.md)
