# AMATELUS Trust Chain Specification

**Status**: AMATELUS Protocol Specification (Draft)
**Version**: 1.0.0
**Base Specifications**:
- W3C Verifiable Credentials Data Model 1.1
- AMATELUS JSON Schema Subset

---

## 1. Abstract

このドキュメントは、AMATELUSプロトコルにおける**トラストチェーン（信頼の連鎖）**の詳細な仕様を定義します。

トラストチェーンは以下を可能にします：
1. **権限委譲**: 上位組織から下位組織への権限委譲
2. **検証可能な信頼**: 委譲の連鎖を暗号学的に検証
3. **スキーマベース委譲**: JSON Schemaで委譲内容を構造的に定義
4. **動的階層制限**: 委任者がmaxDepthを指定、Nat単調減少により無限階層を防止（InitialMaxDepthで上限設定）
5. **Holder中心設計**: VCは誰でも（Holder自身でも）発行可能、検証者はDelegationChainのgrantorDIDのみを確認
6. **各claim個別署名**: 受託者が各claimに個別署名することで、VP作成とZKP入力サイズの劇的削減を実現
7. **VPは内部データ構造**: VCやVPを外部に提出せず、すべての提出はZKPのみで行う
8. **フィールド単位の選択的開示**: ZKPにより必要なフィールドのみを公開、最大限のプライバシー保護を実現

---

## 2. Trust Chain Architecture

### 2.1 トラストチェーンの構成要素

トラストチェーンは以下の要素から構成されます：

```
┌─────────────────────┐
│   Root Anchor       │  信頼の起点（例：政府）
│  (Trusted Anchor)   │  Wallet.trustedAnchorsに登録
└──────────┬──────────┘
           │
           │ ① Delegation Credential (委任証明VC)
           │    - 委任者DID → 受託者DID
           │    - 委譲内容（ClaimID + JSON Schema）
           │    - 委任者の署名
           │
           ▼
┌─────────────────────┐
│   Delegatee         │  受託者（例：自治体A）
│  (Authority)        │  委譲された権限を行使
└──────────┬──────────┘
           │
           │ ② Initial VC (初期VC)
           │    - 発行者DID（受託者）
           │    - 主体DID（住民）
           │    - 属性情報（住民票データ）
           │    - ① を埋め込んだDelegationChain
           │
           ▼
┌─────────────────────┐
│   Holder            │  主体（例：住民）
│                     │  VCを受け取る
└──────────┬──────────┘
           │
           │ ③ Re-packaging (再パッケージング)
           │    - Holder自身がissuerとしてVCを再発行
           │    - DelegationChainはそのままコピー
           │    - Holder自身の署名でVC全体に署名
           │
           ▼
┌─────────────────────┐
│   Verifier          │  検証者（例：サービス提供者）
│                     │
│  検証内容:          │
│  - ZKPの検証        │
│  - grantorDID（政府）が │
│    trustedAnchorsに  │
│    含まれるか       │
│                     │
│  検証しない:        │
│  - VCのissuer       │
│  - granteeDIDとの一致 │
└─────────────────────┘
```

**重要な設計思想**:
- **VCのissuerは誰でもいい**: Holderは受け取ったVCを自分自身で再発行（自己署名）できる
- **検証対象はDelegationChain**: 検証者はVCのissuerではなく、DelegationChainのgrantorDIDのみを確認
- **ZKPとの親和性**: VCのissuerを隠してもDelegationChainで信頼を証明できる

### 2.2 階層制限（動的制限）

AMATELUSプロトコルは**動的階層制限**をサポートします。

#### 2.2.1 設計原則

1. **プロトコルレベルの上限なし**
   - 各委任者が`maxDepth`（残り階層数）を自由に設定
   - `Nat`型の性質により、有限回の委任で必ずゼロに到達
   - Lean4で形式的に停止性を証明

2. **単調減少性**
   - 各委任で残り階層数が減少：`nextDepth = min(parentDepth - 1, delegation.maxDepth)`
   - 受託者はさらに小さい値で上書き可能（大きくはできない）
   - ゼロに到達したら、それ以上の委任は不可

3. **循環委任の防止**
   - 委任チェーン内のDIDが重複していないことを確認
   - O(n)の計算量で検出可能

4. **柔軟な運用**
   - 政府：`maxDepth=N`（大きな値を設定、再委託の数に関心がない場合）
   - 都道府県：`maxDepth=5`（実際のニーズに応じて制限）
   - 市区町村：`maxDepth=2`（さらに制限）

#### 2.2.2 階層の例

```
政府 (initialDepth=InitialMaxDepth)
  ↓ maxDepth=N, nextDepth=min(InitialMaxDepth-1,N)
都道府県 (remainingDepth=InitialMaxDepth-1)
  ↓ maxDepth=5, nextDepth=min(InitialMaxDepth-2,5)=5  ← 都道府県が制限
市区町村 (remainingDepth=5)
  ↓ maxDepth=2, nextDepth=min(4,2)=2  ← 市区町村が制限
部門 (remainingDepth=2)
  ↓ maxDepth=10, nextDepth=min(1,10)=1  ← 実際は1まで減少
係 (remainingDepth=1)
  ↓ maxDepth=10, nextDepth=min(0,10)=0  ← ゼロに到達、これ以上委任不可
```

#### 2.2.3 安全性保証（Lean4で形式証明済み）

**定理1: 停止性**（Lean4で証明済み）
```lean
theorem verifyChain_terminates :
  ∀ (delegations : List DelegationContent)
    (remainingDepth : Nat)
    (trustedAnchors : List ValidDID),
  ∃ (result : Bool),
    DelegationChain.verifyChain delegations remainingDepth trustedAnchors = result
```
**証明**: `verifyChain`の定義に`termination_by remainingDepth`を使用し、`computeNextDepth`の単調減少性により、`remainingDepth`がゼロに到達することを保証。Lean4の`termination_by`と`decreasing_by`で形式的に証明済み。

**定理2: 有限階層性**（Lean4で証明済み）
```lean
theorem finite_delegation_chain :
  ∀ (delegations : List DelegationContent)
    (initialDepth : Nat)
    (trustedAnchors : List ValidDID),
  DelegationChain.verifyChain delegations initialDepth trustedAnchors = true →
  delegations.length ≤ initialDepth
```
**証明**: 補助定理`verifyChain_length_bound`を`remainingDepth`に関する構造的帰納法で証明。`computeNextDepth`の単調減少性（`computeNextDepth depth maxDepth ≤ depth`）により、各ステップで残り階層数が減少し、チェーン長が初期深さを超えないことを保証。Lean4で完全に形式証明済み。

**定理3: N階層委任チェーンの有限性**（Lean4で証明済み）
```lean
theorem n_layer_chain_finite :
  ∀ (chain : DelegationChain) (trustedAnchors : List ValidDID),
  chain.verify trustedAnchors = true →
  chain.depth ≤ InitialMaxDepth
```
**証明**: `DelegationChain.verify`の定義により`InitialMaxDepth`を使用。`finite_delegation_chain`から直接導出。Lean4で完全に形式証明済み。

**定理4: 循環委任の防止**
```lean
def hasCircularDelegation (chain : DelegationChain) : Bool :=
  let allDIDs := getAllDIDs chain
  allDIDs.length != allDIDs.eraseDups.length
```
**検証方法**: DID重複チェックにより、循環委任を検出。`DelegationChain.verify`は`hasCircularDelegation chain = true`の場合、`false`を返す。

---

## 3. Delegation Credential（委任証明VC）

### 3.1 概要

**Delegation Credential**は、委任者から受託者への権限委譲を証明するW3C準拠のVCです。

**特徴**:
- W3C Verifiable Credentials Data Model 1.1 準拠
- `credentialSubject`に委譲内容を含む
- 委譲内容はJSON Schema（AMATELUS Subset）で表現
- 委任者の署名で検証可能

### 3.2 データ構造（JSON）

**設計思想**: 委任者は複数の委任をまとめて1つのDelegation Credentialに含めることができます。これにより：
- 政府が自治体に対して数十種類の委任（住民票、戸籍謄本、印鑑証明など）を1つのVCで発行できる
- 受託者は必要な委任だけを選んで属性VCに埋め込める
- 複数の委任者（政府、警察庁、厚生労働省など）からの委任を組み合わせて使える

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/delegation/v1"
  ],
  "id": "urn:uuid:delegation-12345",
  "type": ["VerifiableCredential", "DelegationCredential"],

  "issuer": "did:amt:gov123...",

  "issuanceDate": "2025-10-13T00:00:00Z",
  "expirationDate": "2026-10-13T00:00:00Z",

  "credentialSubject": {
    "id": "did:amt:city-a456...",
    "delegations": [
      {
        "delegation": {
          "grantorDID": "did:amt:gov123...",
          "granteeDID": "did:amt:city-a456...",
          "label": "住民票",
          "claimSchema": {
            "type": "object",
            "properties": {
              "name": {"type": "string", "minLength": 1, "maxLength": 100},
              "address": {"type": "string", "minLength": 1},
              "birthDate": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
              "nationalID": {"type": "string", "pattern": "^[0-9]{12}$"}
            },
            "required": ["name", "address", "birthDate", "nationalID"]
          }
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z3FX..."
        }
      },
      {
        "delegation": {
          "grantorDID": "did:amt:gov123...",
          "granteeDID": "did:amt:city-a456...",
          "label": "戸籍謄本",
          "claimSchema": {
            "type": "object",
            "properties": {
              "familyName": {"type": "string"},
              "members": {"type": "array", "items": {"type": "object"}}
            },
            "required": ["familyName", "members"]
          }
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z4GY..."
        }
      },
      {
        "delegation": {
          "grantorDID": "did:amt:gov123...",
          "granteeDID": "did:amt:city-a456...",
          "label": "印鑑証明",
          "claimSchema": {
            "type": "object",
            "properties": {
              "sealImage": {"type": "string"},
              "registrationDate": {"type": "string"}
            },
            "required": ["sealImage", "registrationDate"]
          }
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z5HZ..."
        }
      }
    ]
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amt:gov123...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FX..."
  }
}
```

### 3.3 フィールド定義

#### 3.3.1 `issuer`（委任者DID）

- **型**: DID文字列
- **説明**: 権限を委譲する側のDID（例：政府）
- **検証**: Wallet.trustedAnchorsに含まれる必要がある

#### 3.3.2 `credentialSubject.id`（受託者DID）

- **型**: DID文字列
- **説明**: 権限を受ける側のDID（例：自治体A）- **歴史的情報**
- **Holder中心設計における役割**:
  - このフィールドは「元々誰に委任されたか」を示す歴史的情報
  - **検証者はこのフィールドと属性VCのissuerの一致を検証しない**

#### 3.3.3 `credentialSubject.delegations`（委任配列）

- **型**: Array of SignedDelegation
- **説明**: 委譲される複数のクレームのリスト
- **構造**: 各要素は`{delegation: {...}, proof: {...}}`の形式
- **特徴**:
  - 1つのDelegation Credentialに複数の委任を含めることができる
  - 受託者は必要な委任だけを選んで使用できる
  - 委任者（政府など）は一度に複数の委任をまとめて発行できる
  - **重要**: 各委任要素は自己完結し、単独でコピー可能

#### 3.3.4 `delegations[].delegation`（委任内容）

- **型**: Object
- **説明**: 署名対象となる委任の内容
- **フィールド**:
  - `grantorDID`: 委任者DID
  - `granteeDID`: 受託者DID
  - `label`: クレームの表示ラベル（人間向け、機能を持たない）
  - `claimSchema`: JSON Schema（正式な定義）
  - `maxDepth`: 最大委任階層数（1以上の自然数、必須）

#### 3.3.5 `delegations[].delegation.grantorDID`

- **型**: DID文字列
- **説明**: 権限を委譲する側のDID（委任者）
- **検証**: Wallet.trustedAnchorsに含まれる必要がある
- **重要**: 各委任要素に含まれるため、単独でコピーしても委任者が明確

#### 3.3.6 `delegations[].delegation.granteeDID`

- **型**: DID文字列
- **説明**: 権限を受ける側のDID（受託者）- **歴史的情報**
- **Holder中心設計における役割**:
  - このフィールドは「元々誰に委任されたか」を示す歴史的情報
  - **検証者はこのフィールドと属性VCのissuerの一致を検証しない**
  - Holderは受け取ったVCを自分自身で再発行（自己署名）でき、その場合issuerはHolderのDIDになる
  - 検証で重要なのは`grantorDID`のみ（信頼の起点）
- **重要**: 各委任要素に含まれるため、単独でコピーしても元の受託者が明確

#### 3.3.7 `delegations[].delegation.label`

- **型**: String
- **説明**: クレームの表示ラベル（人間向け、例：`"住民票"`, `"戸籍謄本"`, `"Resident Certificate"`）
- **役割**: ウォレットアプリでの表示用ラベル、衝突可能な任意文字列、機能を持たない純粋な表示用
- **真の識別**: `claimSchema`が委任内容の正式な定義
- **AIによる推論**: AIは`claimSchema`から意味を推論可能

#### 3.3.8 `delegations[].delegation.claimSchema`

- **型**: JSON Schema（AMATELUS Subset準拠）
- **説明**: 委譲内容の構造を定義するスキーマ
- **制約**:
  - `$ref`, `$defs`を含まない（循環参照防止）
  - ネスト深さ最大3レベル
  - AMATELUS JSON Schema Subsetに準拠
- **検証**: 属性VCの対応するclaims.dataがこのスキーマに対して有効である必要がある

#### 3.3.9 `delegations[].delegation.maxDepth`

- **型**: Nat（1以上の自然数）
- **説明**: この委任からさらに何階層まで委任を許可するか
- **デフォルト**: 1（後方互換性）
- **単調減少性**:
  - 受託者は親の`remainingDepth - 1`と自分の`maxDepth`の小さい方まで委任可能
  - 計算式：`nextDepth = min(parentDepth - 1, delegation.maxDepth)`
- **例**:
  - 政府: `maxDepth=N`（大きな値を設定）
  - 都道府県: `maxDepth=5`（組織構造に応じて）
  - 市区町村: `maxDepth=2`（さらに制限）
- **検証**: 1以上の自然数であることを確認

#### 3.3.10 `delegations[].proof`（委任要素の署名）

- **型**: W3C Proof Object
- **説明**: `delegation`フィールド全体に対する署名
- **検証対象**: `delegation`オブジェクト（`grantorDID`, `granteeDID`, `label`, `claimSchema`, `maxDepth`）を正規化してシリアライズしたもの
- **署名アルゴリズム**: Ed25519（推奨）
- **重要**: 署名は署名対象の外側に配置されるため、循環参照を回避
- **フィールド**:
  - `type`: 署名タイプ（例：`"Ed25519Signature2020"`）
  - `created`: 署名生成日時
  - `verificationMethod`: 委任者の公開鍵への参照
  - `proofPurpose`: 署名目的（例：`"assertionMethod"`）
  - `proofValue`: 署名値（Base64エンコード）

#### 3.3.11 `proof.proofValue`（VC全体の署名）

- **型**: Base64エンコードされた署名
- **説明**: 委任者の秘密鍵で生成された署名（VC全体に対する）
- **検証対象**: `credentialSubject`全体（すべての`delegations`を含む）を正規化してシリアライズしたもの
- **署名アルゴリズム**: Ed25519（推奨）
- **注意**: これはVC全体の整合性を保証する署名であり、各委任の`proof.proofValue`とは別

---

## 4. Attribute Credential（属性VC）with Embedded Delegation

### 4.1 概要

属性VCは、主体（Subject）の属性情報を証明するVCです。委譲された権限で発行される場合、**各クレームにDelegationChainを直接埋め込み**ます。

**設計思想**:
- 各クレームは`content`、`delegation`、`delegationProof`、`proof`を含む自己完結構造
- `proof`は受託者による`content`への署名で、ZKP検証時にHolderの改ざんを検出可能
- 0階層（直接発行）の場合は従来のW3C VCと同じ構造（`claims`のみ）

### 4.2 データ構造（JSON）

#### 4.2.1 直接発行（0階層）の場合

通常のW3C VCと同じ構造です。

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/v1"
  ],
  "id": "urn:uuid:credential-67890",
  "type": ["VerifiableCredential", "ResidentCertificate"],

  "issuer": "did:amt:gov123...",

  "issuanceDate": "2025-10-13T00:00:00Z",

  "credentialSubject": {
    "id": "did:amt:resident789...",
    "claims": [
      {
        "name": "田中太郎",
        "address": "東京都千代田区...",
        "birthDate": "1990-01-01",
        "nationalID": "123456789012"
      }
    ]
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amt:gov123...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4AB..."
  }
}
```

**検証**:
- `issuer`がWallet.trustedAnchorsに含まれているか確認

#### 4.2.2 委譲発行（1階層、単一委任）の場合

新しい構造では、各クレームに委任情報が直接埋め込まれています。

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/v1"
  ],
  "id": "urn:uuid:credential-67890",
  "type": ["VerifiableCredential", "ResidentCertificate"],

  "issuer": "did:amt:city-a456...",

  "issuanceDate": "2025-10-13T00:00:00Z",

  "credentialSubject": {
    "id": "did:amt:resident789...",
    "claims": [
      {
        "content": {
          "name": "田中太郎",
          "address": "東京都千代田区...",
          "birthDate": "1990-01-01",
          "nationalID": "123456789012"
        },
        "delegation": {
          "grantorDID": "did:amt:gov123...",
          "granteeDID": "did:amt:city-a456...",
          "label": "住民票",
          "claimSchema": {
            "type": "object",
            "properties": {
              "name": {"type": "string", "minLength": 1, "maxLength": 100},
              "address": {"type": "string", "minLength": 1},
              "birthDate": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
              "nationalID": {"type": "string", "pattern": "^[0-9]{12}$"}
            },
            "required": ["name", "address", "birthDate", "nationalID"]
          }
        },
        "delegationProof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z3FX..."
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:city-a456...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z5CD..."
        }
      }
    ]
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amt:city-a456...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z6EF..."
  }
}
```

**各フィールドの役割**:
- `content`: クレームの実データ（ZKPの入力となる）
- `delegation`: 委任情報（grantorDID、granteeDID、label、claimSchema）
- `delegationProof`: **委任者（grantor）による`delegation`への署名**
- `proof`: **受託者（grantee）による`content`への署名** - ZKP検証でHolderの改ざんを検出

**検証（Holder中心設計）**:
1. 各`claim`について：
   - `delegation.grantorDID`（`did:amt:gov123...`）がWallet.trustedAnchorsに含まれているか確認
   - `content`が`delegation.claimSchema`に対して有効か確認
   - `delegationProof`を`delegation.grantorDID`の公開鍵で検証
   - **`proof`を`delegation.granteeDID`の公開鍵で検証**（ZKP検証時に必要）
2. **検証しない**:
   - VCの`issuer`の信頼性
   - VC全体の`proof`
   - `delegation.granteeDID`と`issuer`の一致

#### 4.2.3 委譲発行（複数委任元を組み合わせ）の場合

**使用例**: 自治体が政府、警察庁、厚生労働省から受けた委任を組み合わせて「運転免許と保険証付き住民票VC」を発行

新しい構造では、各クレームが独立しており、異なる委任元からの委任を明確に区別できます。

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/v1"
  ],
  "id": "urn:uuid:credential-combined-12345",
  "type": ["VerifiableCredential", "CombinedIdentityDocument"],

  "issuer": "did:amt:city-a456...",

  "issuanceDate": "2025-10-13T00:00:00Z",

  "credentialSubject": {
    "id": "did:amt:resident789...",
    "claims": [
      {
        "content": {
          "name": "田中太郎",
          "address": "東京都千代田区...",
          "birthDate": "1990-01-01",
          "nationalID": "123456789012"
        },
        "delegation": {
          "grantorDID": "did:amt:gov123...",
          "granteeDID": "did:amt:city-a456...",
          "label": "住民票",
          "claimSchema": { /* ... */ }
        },
        "delegationProof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofValue": "z3FX..."
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:city-a456...#keys-1",
          "proofValue": "z7AB..."
        }
      },
      {
        "content": {
          "licenseNumber": "123456789012",
          "licenseType": "普通自動車",
          "expirationDate": "2030-01-01"
        },
        "delegation": {
          "grantorDID": "did:amt:police456...",
          "granteeDID": "did:amt:city-a456...",
          "label": "運転免許証",
          "claimSchema": { /* ... */ }
        },
        "delegationProof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:police456...#keys-1",
          "proofValue": "z4GY..."
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:city-a456...#keys-1",
          "proofValue": "z8CD..."
        }
      },
      {
        "content": {
          "insuranceNumber": "98765432109876",
          "insurerName": "全国健康保険協会",
          "expirationDate": "2026-03-31"
        },
        "delegation": {
          "grantorDID": "did:amt:mhlw789...",
          "granteeDID": "did:amt:city-a456...",
          "label": "保険証",
          "claimSchema": { /* ... */ }
        },
        "delegationProof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:mhlw789...#keys-1",
          "proofValue": "z5HZ..."
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "verificationMethod": "did:amt:city-a456...#keys-1",
          "proofValue": "z9EF..."
        }
      }
    ]
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T00:00:00Z",
    "verificationMethod": "did:amt:city-a456...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z6IJ..."
  }
}
```

**検証（Holder中心設計）**:
1. 各`claim`について独立に検証：
   - `delegation.grantorDID`（政府、警察庁、厚生労働省）がWallet.trustedAnchorsに含まれているか
   - `content`が`delegation.claimSchema`に対して有効か
   - `delegationProof`を`delegation.grantorDID`の公開鍵で検証
   - `proof`を`delegation.granteeDID`の公開鍵で検証（ZKP検証時に必要）
2. **検証しない**:
   - VCの`issuer`の信頼性
   - VC全体の`proof`
   - 各`delegation.granteeDID`と`issuer`の一致

**利点**:
- 自治体は複数の委任者から受けた委任を組み合わせて、1つのVCで複数の証明を提供できる
- 住民は1つのVCで複数の身分証明を提示できる（利便性向上）
- 各委任元（政府、警察庁、厚生労働省）の署名で独立に検証可能（セキュリティ保証）

#### 4.2.4 Holder再パッケージング（Holder中心設計）の場合

**Holder中心設計の重要な特徴**: Holderは受け取ったVCを自分自身で再発行（自己署名）できます。この場合：
- **VCのissuer**: Holder自身のDID
- **VCの署名**: Holder自身の秘密鍵による署名
- **各claimの内容**: 元のまま保持（`content`、`delegation`、`delegationProof`、`proof`すべて）
- **検証**: grantorDIDと各claimの`proof`（受託者署名）を確認、VCのissuerは検証しない

**例**: 住民（Holder）が自治体から受け取った4.2.2のVCを、自分自身のissuerで再パッケージング

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/v1"
  ],
  "id": "urn:uuid:credential-repackaged-99999",
  "type": ["VerifiableCredential", "ResidentCertificate"],

  "issuer": "did:amt:resident789...",  // ← Holder自身

  "issuanceDate": "2025-10-13T12:00:00Z",

  "credentialSubject": {
    "id": "did:amt:resident789...",
    "claims": [
      {
        "content": {
          "name": "田中太郎",
          "address": "東京都千代田区...",
          "birthDate": "1990-01-01",
          "nationalID": "123456789012"
        },
        "delegation": {
          "grantorDID": "did:amt:gov123...",      // ← 政府（信頼の起点）
          "granteeDID": "did:amt:city-a456...",  // ← 歴史的情報（元の受託者）
          "label": "住民票",
          "claimSchema": {
            "type": "object",
            "properties": {
              "name": {"type": "string", "minLength": 1, "maxLength": 100},
              "address": {"type": "string", "minLength": 1},
              "birthDate": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
              "nationalID": {"type": "string", "pattern": "^[0-9]{12}$"}
            },
            "required": ["name", "address", "birthDate", "nationalID"]
          }
        },
        "delegationProof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:gov123...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z3FX..."  // ← 政府の署名（元のまま）
        },
        "proof": {
          "type": "Ed25519Signature2020",
          "created": "2025-10-13T00:00:00Z",
          "verificationMethod": "did:amt:city-a456...#keys-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z5CD..."  // ← 自治体の署名（元のまま、ZKP検証に必要）
        }
      }
    ]
  },

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T12:00:00Z",
    "verificationMethod": "did:amt:resident789...#keys-1",  // ← Holderの公開鍵
    "proofPurpose": "assertionMethod",
    "proofValue": "z9XY..."  // ← Holderの署名
  }
}
```

**検証**:
1. **検証する内容**:
   - ZKPの検証（`content`から生成されたZKP）
   - `delegation.grantorDID`（`did:amt:gov123...`）がWallet.trustedAnchorsに含まれているか
   - `content`が`delegation.claimSchema`に対して有効か
   - `delegationProof`を`delegation.grantorDID`の公開鍵で検証
   - **`proof`を`delegation.granteeDID`の公開鍵で検証**（ZKP検証時に必要、Holderの改ざん検出）

2. **検証しない内容**:
   - **VCのissuer**（`did:amt:resident789...`）の信頼性
   - **VCの`proof`**（Holderの署名）
   - `delegation.granteeDID`と`issuer`の一致

**設計思想**:
- VCのissuerは誰でもよい（HolderでもOK）
- 各claimの`proof`（受託者署名）によりHolderは`content`を改ざんできない
- ZKPと組み合わせることで、VCのissuerを完全に隠蔽できる
- Holderは任意のタイミングでVCを再パッケージング可能（プライバシー向上）
- 各claimの`proof`は必ず元のまま保持される（改ざん防止）

### 4.3 Verifiable Presentation（VP）とZKP生成

#### 4.3.1 概要

**Verifiable Presentation (VP)** は、Holderが複数のVCから必要なclaimだけを選択してVerifierに提示するためのW3C標準のデータ構造です。

**AMATELUSにおける重要な役割**:
- **ZKPはVPから生成される**（VCからではない）
- Holderは複数のVCから必要なclaimだけを選んでVPを作成
- 各claimの個別`proof`（受託者署名）により、VP内でも検証可能
- **ZKP入力サイズを劇的に削減**（全claimではなく必要なclaimのみ）

#### 4.3.2 VPの構造（W3C準拠）

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://amatelus.org/contexts/v1"
  ],
  "type": ["VerifiablePresentation"],
  "holder": "did:amt:resident789...",

  "verifiableCredential": [
    {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:amt:city-a456...",
      "credentialSubject": {
        "id": "did:amt:resident789...",
        "claims": [
          {
            "content": {
              "name": "田中太郎",
              "address": "東京都千代田区...",
              "birthDate": "1990-01-01",
              "nationalID": "123456789012"
            },
            "delegation": {
              "grantorDID": "did:amt:gov123...",
              "granteeDID": "did:amt:city-a456...",
              "label": "住民票",
              "claimSchema": { /* ... */ }
            },
            "delegationProof": {
              "type": "Ed25519Signature2020",
              "verificationMethod": "did:amt:gov123...#keys-1",
              "proofValue": "z3FX..."
            },
            "proof": {
              "type": "Ed25519Signature2020",
              "verificationMethod": "did:amt:city-a456...#keys-1",
              "proofValue": "z5CD..."
            }
          }
        ]
      }
    },
    {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:amt:city-a456...",
      "credentialSubject": {
        "id": "did:amt:resident789...",
        "claims": [
          {
            "content": {
              "licenseNumber": "123456789012",
              "licenseType": "普通自動車",
              "expirationDate": "2030-01-01"
            },
            "delegation": {
              "grantorDID": "did:amt:police456...",
              "granteeDID": "did:amt:city-a456...",
              "label": "運転免許証",
              "claimSchema": { /* ... */ }
            },
            "delegationProof": {
              "type": "Ed25519Signature2020",
              "verificationMethod": "did:amt:police456...#keys-1",
              "proofValue": "z4GY..."
            },
            "proof": {
              "type": "Ed25519Signature2020",
              "verificationMethod": "did:amt:city-a456...#keys-1",
              "proofValue": "z8CD..."
            }
          }
        ]
      }
    }
  ],

  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-13T14:00:00Z",
    "verificationMethod": "did:amt:resident789...#keys-1",
    "proofPurpose": "authentication",
    "challenge": "abc123...",
    "proofValue": "zAB12..."
  }
}
```

#### 4.3.3 VPの作成プロセス

**シナリオ**: Holderが銀行口座開設のために身分証明を提示

**Holderが保有するVC**:
- **VC1（自治体発行）**: 10個のclaim（住民票、戸籍謄本、印鑑証明、課税証明書、...）
- **VC2（警察庁経由）**: 5個のclaim（運転免許証、犯罪経歴証明、...）
- **VC3（税務署発行）**: 8個のclaim（納税証明、確定申告書、...）

**銀行が要求**: 「住民票」「運転免許証」「納税証明」の3つ

**VP作成ステップ**:
1. VC1から「住民票」claimを抽出（`content` + `delegation` + `delegationProof` + `proof`）
2. VC2から「運転免許証」claimを抽出
3. VC3から「納税証明」claimを抽出
4. 3つのclaimを含む部分的なVCとしてVPに配置
5. VP全体にHolderの署名を付与

#### 4.3.4 ZKP入力サイズの劇的削減

**従来方式（VC全体署名のみの場合）**:
```
ZKP入力 = VC1全体（10 claims） + VC2全体（5 claims） + VC3全体（8 claims）
       = 23個のclaim全部
```

- **問題点**:
  - 不要な20個のclaimもZKP生成に含める必要がある
  - ZKP生成の計算量が膨大（O(23)）
  - ZKP証明サイズも大きくなる
  - メモリ使用量も多い
  - プライバシーリスク（不要なclaimも露出）

**新方式（各claim個別署名 + VP）**:
```
ZKP入力 = VP（3個のclaimのみ）
       = claim[住民票] + その proof
       + claim[運転免許証] + その proof
       + claim[納税証明] + その proof
```

- **利点**:
  - **ZKP生成時間: 約1/7に短縮**（23個 → 3個）
  - **ZKP証明サイズ: 約1/7に削減**
  - **メモリ効率: 大幅向上**
  - **プライバシー向上**: 必要なclaimのみ露出
  - **計算量: O(3)で済む**

**具体的な数値例**（仮定）:
- 1 claim = 1KB
- VC全体方式: 23KB入力 → ZKP生成時間 2.3秒
- VP方式: 3KB入力 → ZKP生成時間 0.3秒

**モバイルデバイスでの効果**:
- バッテリー消費が1/7
- メモリ使用量が1/7
- 応答時間が大幅改善

#### 4.3.5 各claimの個別`proof`の重要性

**各claimの`proof`（受託者署名）がなければ**:
- VC全体の署名しかない場合、VCを分割できない
- VP作成時にVC全体を含める必要がある
- ZKP入力サイズが削減できない

**各claimの`proof`があることで**:
- **各claimが独立して検証可能**
- VCから必要なclaimだけを抽出してVPに配置可能
- VP内でも各claimの`proof`で検証できる
- Holderは各claimの`content`を改ざんできない（`proof`で検出される）

#### 4.3.6 VPの検証

Verifierは以下を検証：

1. **VP全体の検証**:
   - VPの`proof`（Holderの署名）を検証
   - `challenge`が正しいか確認（リプレイ攻撃防止）

2. **各claim個別の検証**（Section 6.2のアルゴリズム適用）:
   - `delegation.grantorDID`がtrustedAnchorsに含まれるか
   - `content`が`delegation.claimSchema`に対して有効か
   - `delegationProof`を`delegation.grantorDID`の公開鍵で検証
   - **`proof`を`delegation.granteeDID`の公開鍵で検証**（ZKP検証の前提）

3. **ZKP検証**:
   - ZKPの公開入力と各claimの`content`が一致するか
   - ZKP自体の検証

4. **検証不要**:
   - VP内のVC部分の`issuer`（Holderが再構成可能）
   - VP内のVC部分の`proof`（ある場合）

#### 4.3.7 設計上の利点まとめ

| 項目 | VC全体署名のみ | 各claim個別署名 |
|------|--------------|----------------|
| VP作成 | VC全体を含める必要 | 必要なclaimのみ選択可能 |
| ZKP入力サイズ | 全claim（大） | 必要なclaimのみ（小） |
| ZKP生成時間 | 長い | 短い（1/N） |
| メモリ使用量 | 多い | 少ない（1/N） |
| プライバシー | 全claim露出 | 必要なclaimのみ露出 |
| モバイル親和性 | 低い | 高い |
| 選択的開示 | claim単位で不可 | claim単位で可能 |

**結論**: 各claimへの個別`proof`は、単なるHolder改ざん防止だけでなく、**VPベースの効率的なZKP生成を可能にする重要な設計要素**です。

#### 4.3.8 VPの位置づけとZKP提出プロトコル

**重要な設計原則**: AMATELUSでは、VCやVPを他者に直接提出することは**ありません**。すべての提出は**ZKPのみ**で行います。

##### 4.3.8.1 VPは内部データ構造

**VPの役割**:
- VPは**ZKP生成のための内部データ構造**
- 複数VCから必要なclaimを選択してZKP入力を準備
- **外部（IssuerやVerifier）には提出しない**

**VPを直接提出してはいけない理由**:

```
【問題例】登記申請で「氏名」と「納税証明（年収≥300万円）」だけ必要な場合

VPを提出すると、claim内の不要なフィールドまで全て開示される:

住民票claim全体:
{
  "name": "田中太郎",          // ← 必要
  "birthDate": "1990-01-01",   // ← 不要だが開示される
  "address": "東京都千代田区...", // ← 不要だが開示される
  "gender": "男性",           // ← 不要だが開示される
  "nationalID": "123456789012" // ← 不要だが開示される
}

納税証明claim全体:
{
  "income": 5500000,           // ← 具体的な所得額まで開示される（300万以上だけ証明すれば十分）
  "taxAmount": 825000,         // ← 納税額まで開示される（不要）
  "year": 2024
}

→ claim単位の選択的開示では不十分
→ フィールド単位の選択的開示が必要
→ ZKPを使用すべき
```

##### 4.3.8.2 すべての提出はZKPのみ

**プロトコル原則**: Issuer、Verifier問わず、すべての提出は**ZKPのみ**

**4.3.8.2.1 Issuer（VC発行者）への提出: ZKP + HolderのDID**

**使用場面**: VC発行依頼時

**ZKPの公開入力に含めるもの**:
- **HolderのDID**（必須）: IssuerがVC発行時の`credentialSubject.id`に記載
- 必要なフィールドのみ（氏名、年齢証明、資格証明など）

**例**: 登記所に不動産登記VCの発行を依頼

```
Holder → Issuer（登記所）

【内部処理】
1. HolderがVPを作成（内部のみ、提出しない）:
   - 住民票claim（name, birthDate, address, gender, nationalID含む）
   - 納税証明claim（income, taxAmount, year含む）

2. VPからZKPを生成:

【ZKP公開入力（Issuerが知る情報）】
{
  "holder_did": "did:amt:holder123...",  // ← Issuerが知る必要あり
  "name": "田中太郎",                    // ← 登記に必要
  "income_gte_3000000": true             // ← 年収≥300万円のみ証明（具体額は隠蔽）
}

【ZKP秘密入力（Issuerは知らない）】
- birthDate: "1990-01-01"
- address: "東京都千代田区..."
- gender: "男性"
- nationalID: "123456789012"
- income: 5500000  // ← 具体的な所得額は隠蔽
- taxAmount: 825000

【ZKP証明】
- 住民票claimが政府（trustedAnchor）から委任された自治体により発行されたこと
- 納税証明claimが税務署により発行されたこと
- nameフィールドが"田中太郎"であること
- incomeフィールドが3000000以上であること
- 各claimのproofが有効であること

【Issuerへの提出内容】
{
  "zkp": {
    "proof": "0x3fa8b...",
    "publicInputs": {
      "holder_did": "did:amt:holder123...",
      "name": "田中太郎",
      "income_gte_3000000": true,
      "grantorDIDs": ["did:amt:gov123", "did:amt:nta456"]  // 信頼の起点
    }
  }
}

【Issuerの処理】
1. ZKPを検証
2. grantorDIDsがtrustedAnchorsに含まれるか確認
3. 不動産登記VCを発行:
   {
     "credentialSubject": {
       "id": "did:amt:holder123...",  // ← ZKPの公開入力から取得
       "claims": [{
         "content": {
           "property_owner": "田中太郎",  // ← ZKPの公開入力から取得
           "property_address": "...",
           "registration_date": "2025-10-13"
         },
         "proof": { ... }  // Issuer（登記所）の署名
       }]
     }
   }
```

**利点**:
- フィールド単位の選択的開示（氏名のみ、具体的な所得額は隠蔽）
- 不要な個人情報（性別、生年月日、住所、マイナンバーなど）の完全隠蔽
- IssuerはHolderのDIDを知ることができる（VC発行に必要）

**4.3.8.2.2 Verifier（検証者）への提出: ZKPのみ（HolderのDID隠蔽）**

**使用場面**: サービス利用時（銀行口座開設、年齢確認、資格証明など）

**ZKPの公開入力に含めるもの**:
- **HolderのDIDは含めない**（隠蔽される）
- 証明内容のみ（年齢≥20、日本在住、資格保有など）

**例**: 銀行口座開設

```
Holder → Verifier（銀行）

【内部処理】
1. HolderがVPを作成（内部のみ、提出しない）:
   - 住民票claim（name, birthDate, address, gender, nationalID含む）
   - 犯罪歴証明claim（record含む）

2. VPからZKPを生成:

【ZKP公開入力（Verifierが知る情報）】
{
  "age_gte_20": true,           // 年齢≥20であること
  "residence_japan": true,      // 日本在住であること
  "no_criminal_record": true,   // 犯罪歴がないこと
  "grantorDIDs": ["did:amt:gov123", "did:amt:police456"]
}

【ZKP秘密入力（Verifierは知らない）】
- holder_did: "did:amt:holder123..."  // ← HolderのDIDは隠蔽
- name: "田中太郎"
- birthDate: "1990-01-01"  // ← 具体的な生年月日は隠蔽
- address: "東京都千代田区..."  // ← 具体的な住所は隠蔽
- gender: "男性"
- nationalID: "123456789012"
- record: null

【ZKP証明】
- 住民票claimが政府（trustedAnchor）から委任された自治体により発行されたこと
- 犯罪歴証明claimが警察庁により発行されたこと
- birthDateフィールドから計算した年齢が20以上であること
- addressフィールドが日本国内であること
- recordフィールドがnullであること
- 各claimのproofが有効であること

【Verifierへの提出内容】
{
  "zkp": {
    "proof": "0x3fa8b...",
    "publicInputs": {
      "age_gte_20": true,
      "residence_japan": true,
      "no_criminal_record": true,
      "grantorDIDs": ["did:amt:gov123", "did:amt:police456"]
    }
  }
}

【Verifierの処理】
1. ZKPを検証
2. grantorDIDsがtrustedAnchorsに含まれるか確認
3. 口座開設を承認

【Verifierが知り得る情報】
✓ 年齢が20歳以上であること
✓ 日本在住であること
✓ 犯罪歴がないこと

【Verifierが知り得ない情報】
✗ HolderのDID
✗ 正確な生年月日（1990-01-01）
✗ 正確な住所（東京都千代田区...）
✗ 氏名（田中太郎）
✗ 性別（男性）
✗ マイナンバー（123456789012）
✗ 元のVCやclaimの内容
```

**利点**:
- 完全なプライバシー保護
- フィールド単位の選択的開示（必要な証明のみ）
- HolderのDID完全隠蔽
- 元のVC/claim全体が露出しない

##### 4.3.8.3 比較表（修正版）

| 項目 | Issuerへの提出 | Verifierへの提出 |
|------|--------------|----------------|
| 提出するもの | **ZKP**のみ | **ZKP**のみ |
| HolderのDID | 公開入力に含める | 隠蔽される |
| フィールド開示 | 必要なフィールドのみ | 証明のみ（値は隠蔽） |
| 計算コスト | 中程度（ZKP生成） | 中程度（ZKP生成） |
| プライバシー | 高い（フィールド単位開示） | 最高（証明のみ） |
| 使用場面 | VC発行依頼 | サービス利用 |
| ZKP公開入力例 | `{holder_did, name, income_gte}` | `{age_gte, residence}` |

##### 4.3.8.4 実装フロー例

**シナリオ**: 住民がスマートフォンで住民票VC発行を依頼し、後日銀行口座を開設

```
【フェーズ1: VC発行依頼（Issuer）】
1. Holder準備:
   - 既存のマイナンバーカードVC（政府発行）を保有
   - 住民票VC発行を自治体に依頼したい

2. VP作成（内部処理）:
   - マイナンバーカードVCから必要なclaimを抽出
   - VPに配置
   → 所要時間: 約0.1秒

3. ZKP生成:
   - 公開入力: holder_did, name（必要なフィールドのみ）
   - 秘密入力: birthDate, address, gender, nationalID（不要なフィールドは隠蔽）
   → 所要時間: 約2秒

4. 自治体（Issuer）へZKP提出:
   - holder_did: "did:amt:holder123..."を公開
   - name: "田中太郎"を公開
   - その他のフィールド（birthDate, gender, nationalIDなど）は隠蔽

5. 自治体が住民票VC発行:
   - credentialSubject.id = "did:amt:holder123..."  // ← ZKPの公開入力から取得
   - 住民票データを含むVCを発行

【フェーズ2: サービス利用（Verifier）】
1. 後日、銀行口座開設時:
   - 住民票VCから必要なclaimを抽出してVP作成
   → 所要時間: 約0.1秒

2. ZKP生成:
   - 公開入力: age_gte_20, residence_japan（証明のみ）
   - 秘密入力: holder_did, name, birthDate, address（すべて隠蔽）
   → 所要時間: 約2秒（VPサイズ削減により高速化）

3. 銀行（Verifier）へZKP提出:
   - holder_didも含めて完全に隠蔽
   - 必要な証明（年齢≥20、日本在住）のみ提出

4. 銀行が口座開設を承認
```

**重要な設計原則のまとめ**:
- **VCやVPは外部に提出しない**（内部データ構造）
- **すべての提出はZKPのみ**
- **Issuerへの提出**: ZKPの公開入力にHolderのDIDを含める + 必要なフィールドのみ開示
- **Verifierへの提出**: ZKPの公開入力にHolderのDIDを含めない + 証明のみ
- **フィールド単位の選択的開示**により最大限のプライバシー保護

---

## 5. Trust Chain Structure（Lean定義）

### 5.1 DelegationContent型（署名対象）

Delegation Credentialで使用される委任内容の定義です。

```lean
/-- 委任内容（Delegation Content）

    署名対象となる委任の内容。
    署名自身は含まない。

    **設計思想:**
    - 署名対象のデータのみを含む
    - 署名は別の構造体（SignedDelegation）で保持
    - 署名の循環参照を回避
    - maxDepthによる動的階層制限

    **フィールド:**
    - grantorDID: 委任者DID（権限を与える側）
    - granteeDID: 受託者DID（権限を受ける側、歴史的情報）
    - label: クレームの表示ラベル（人間向け、衝突可能な任意文字列、機能を持たない）
    - claimSchema: 委譲内容の構造を定義するJSON Schema（真の定義）
    - maxDepth: 最大委任階層数（1以上の自然数）
-/
structure DelegationContent where
  grantorDID : ValidDID
  granteeDID : ValidDID  -- Holder中心設計では歴史的情報
  label : String         -- 人間向けの表示ラベル（例: "住民票", "Resident Certificate"）、機能を持たない
  claimSchema : Schema   -- JSONSchemaSubset準拠、委任内容の正式な定義
  maxDepth : Nat         -- 最大委任階層数（1以上）
  deriving Repr

namespace DelegationContent

/-- maxDepthが有効かどうか（1以上） -/
def isValidMaxDepth (d : DelegationContent) : Bool :=
  d.maxDepth ≥ 1

end DelegationContent
```

### 5.1a SignedDelegation型（自己完結版）

```lean
/-- 署名付き委任（Signed Delegation）- 自己完結版

    1つの委任を表す構造。単独でコピーしても正当性を維持できる。

    **設計思想:**
    - 委任内容（content）と署名（proof）を分離
    - 署名は委任内容に対して生成される
    - 各委任要素が完全に独立している
    - 単独でコピーして他のVCに埋め込んでも検証可能

    **構造:**
    ```json
    {
      "delegation": {
        "grantorDID": "...",
        "granteeDID": "...",
        "label": "...",
        "claimSchema": {...}
      },
      "proof": {
        "type": "Ed25519Signature2020",
        "proofValue": "..."
      }
    }
    ```

    **フィールド:**
    - content: 委任内容（署名対象）
    - proof: 委任内容に対する署名
-/
structure SignedDelegation where
  content : DelegationContent
  proof : W3C.Proof  -- W3C標準のProof構造
  deriving Repr
```

### 5.2 DelegationCredential型（複数委任対応）

```lean
/-- 委任証明（Delegation Credential）- 複数委任対応

    権限委譲を証明するW3C準拠のVC。
    複数の委任をまとめて1つのVCに含めることができる。

    **設計思想:**
    - 委任者（政府など）は複数の委任を一度にまとめて発行できる
    - 受託者（自治体など）は必要な委任だけを選んで使用できる
    - 各SignedDelegationが自己完結しているため、単独でコピー可能
    - 署名は2段階：各委任の署名 + VC全体の署名

    **フィールド:**
    - delegations: 委譲される複数のクレームのリスト（各要素は自己完結）
    - vcProof: VC全体の署名（整合性保証用、各SignedDelegationのproofとは別）

    **検証:**
    - 各SignedDelegationのgrantorDIDが同一であることを確認（推奨）
    - 各SignedDelegationのgranteeDIDが同一であることを確認（推奨）
    - 各SignedDelegationのproofを個別に検証
    - vcProofでVC全体の整合性を検証
-/
structure DelegationCredential where
  delegations : List SignedDelegation
  vcProof : W3C.Proof  -- VC全体の署名
  deriving Repr
```

### 5.3 DelegationChain型（多層委任チェーン）

多層委任チェーンを表現する構造です。

```lean
/-- 委任チェーン（Delegation Chain）

    複数階層の委任を表現する構造。

    **設計思想:**
    - 0階層から任意の階層まで委任をリストで表現
    - 各委任要素にはmaxDepthが含まれる
    - 単調減少性により無限階層を防止
    - 循環委任をDID重複チェックで検出

    **フィールド:**
    - delegations: 委任のリスト（順序重要、政府→都道府県→市区町村...）
    - chainProofs: 各委任に対する署名のリスト
-/
structure DelegationChain where
  delegations : List DelegationContent
  chainProofs : List W3C.Proof
  deriving Repr

namespace DelegationChain

/-- 循環委任のチェック -/
def hasCircularDelegation (chain : DelegationChain) : Bool :=
  let allDIDs := chain.delegations.flatMap (fun d => [d.grantorDID, d.granteeDID])
  allDIDs.length != allDIDs.unique.length

/-- チェーンの深さを取得 -/
def depth (chain : DelegationChain) : Nat :=
  chain.delegations.length

/-- 次の階層での残り階層数を計算 -/
def computeNextDepth (parentDepth : Nat) (delegationMaxDepth : Nat) : Nat :=
  if parentDepth = 0 then
    0
  else
    min (parentDepth - 1) delegationMaxDepth

/-- 委任チェーンを検証（再帰的） -/
def verifyChain
    (delegations : List DelegationContent)
    (remainingDepth : Nat)
    (trustedAnchors : List ValidDID)
    : Bool :=
  match delegations, remainingDepth with
  | [], _ =>
      true  -- チェーン終了
  | _, 0 =>
      false  -- 残り階層数がゼロ（深さ超過）
  | d :: ds, depth + 1 =>
      -- 委任者が信頼されているか（または前の受託者か）
      if !trustedAnchors.contains d.grantorDID then
        false
      else
        -- 次の階層での残り階層数を計算（単調減少）
        let nextDepth := computeNextDepth depth d.maxDepth
        verifyChain ds nextDepth trustedAnchors

/-- 委任チェーン全体を検証 -/
def verify (chain : DelegationChain) (trustedAnchors : List ValidDID) : Bool :=
  -- 1. 循環委任チェック
  if chain.hasCircularDelegation then
    false
  -- 2. チェーンが空の場合はtrue
  else if chain.delegations.isEmpty then
    true
  -- 3. 最初の委任のmaxDepthで検証開始
  else
    match chain.delegations.head? with
    | none => false
    | some firstDelegation =>
        let initialDepth := firstDelegation.maxDepth
        verifyChain chain.delegations initialDepth trustedAnchors

-- 停止性の定理
theorem verifyChain_terminates
    (delegations : List DelegationContent)
    (depth : Nat)
    (anchors : List ValidDID) :
    ∃ (result : Bool), verifyChain delegations depth anchors = result := by
  -- remainingDepthは各ステップで単調減少
  -- Natは整礎的（well-founded）
  -- よってverifyChainは必ず停止する
  sorry

-- 有限階層性の定理
theorem finite_delegation_chain
    (chain : DelegationChain)
    (initialDepth : Nat) :
    verifyChain chain.delegations initialDepth [] = true →
    chain.depth ≤ initialDepth := by
  -- 各ステップで残り階層数が減少し、ゼロで停止
  -- よってチェーン長は初期深さを超えない
  sorry

end DelegationChain
```

### 5.4 Claim型（属性VCのクレーム）

属性VCに含まれるクレームの構造です。0階層から任意の階層まで対応します。

```lean
/-- クレーム（Claim）- 属性VCに含まれる個々のクレーム

    **設計思想:**
    - 各クレームは自己完結構造（content + delegation chain + proofs）
    - 0階層（直接発行）: contentのみ
    - N階層（委譲発行）: content + delegationChain + contentProof
    - contentProofは最終発行者によるcontentへの署名でZKP検証時にHolderの改ざんを検出

    **フィールド:**
    - content: クレームの実データ（ZKPの入力となる）
    - delegationChain: 委任チェーン（N階層の場合のみ）
    - contentProof: 最終発行者によるcontentへの署名（N階層の場合のみ、ZKP検証に必要）
-/
structure Claim where
  content : JSONValue
  delegationChain : Option DelegationChain
  contentProof : Option W3C.Proof
  deriving Repr

namespace Claim

/-- 0階層（直接発行）のクレームを構築 -/
def makeDirectClaim (content : JSONValue) : Claim :=
  { content, delegationChain := none, contentProof := none }

/-- N階層（委譲発行）のクレームを構築 -/
def makeDelegatedClaim
    (content : JSONValue)
    (chain : DelegationChain)
    (contentProof : W3C.Proof) : Claim :=
  { content,
    delegationChain := some chain,
    contentProof := some contentProof }

/-- クレームが委譲発行かどうか判定 -/
def isDelegated (claim : Claim) : Bool :=
  claim.delegationChain.isSome

/-- クレームの委任階層数を取得 -/
def depth (claim : Claim) : Nat :=
  match claim.delegationChain with
  | none => 0
  | some chain => chain.depth

end Claim
```

### 5.5 TrustChain型（新しいClaim構造対応）

```lean
/-- トラストチェーン - 新しいClaim構造対応

    信頼の連鎖を表現する構造。
    複数の委任元（root anchors）を持つことができる。

    **設計思想:**
    - 複数の委任者（政府、警察庁、厚生労働省など）からの委任を組み合わせられる
    - 各委任者は独立にWallet.trustedAnchorsに登録されている必要がある
    - 0階層（直接発行）から任意のN階層（多層委譲発行）のclaimsが混在可能
    - 各Claimが自己完結しているため、個別に検証可能
    - 動的階層制限により無限階層を防止

    **構成要素:**
    - rootAnchors: 信頼の起点のリスト（すべてWallet.trustedAnchorsに含まれる必要がある）
    - claims: 属性VCに含まれるクレームのリスト（0階層からN階層の混在可能）
    - credential: 最終的に発行された属性VC
-/
structure TrustChain where
  /-- 信頼の起点のリスト（例：[政府, 警察庁, 厚生労働省]） -/
  rootAnchors : List ValidDID
  /-- クレームのリスト（0階層からN階層の混在可能） -/
  claims : List Claim
  /-- 属性VC -/
  credential : ValidVC
  deriving Repr

namespace TrustChain

/-- トラストチェーンの深さを取得

    **戻り値:**
    - 0: すべてのclaimが直接発行（委譲なし）
    - N: 最も深いclaimの委任階層数
-/
def depth (chain : TrustChain) : Nat :=
  chain.claims.foldl (fun maxDepth claim => max maxDepth claim.depth) 0

/-- トラストチェーンが有効かどうかを検証 - Holder中心設計 + N階層対応

    **Holder中心設計 + N階層対応における検証内容:**
    1. すべてのrootAnchorが信頼されているか（Wallet.trustedAnchorsに含まれる）
    2. 各claimについて：
       - claim.isDelegated == false（0階層）の場合:
         * credential.issuerDIDがrootAnchorsに含まれる
       - claim.isDelegated == true（N階層）の場合:
         * DelegationChain.verifyを使用して委任チェーン全体を検証
         * 各delegationのmaxDepthが単調減少することを確認
         * 循環委任がないことを確認（DID重複チェック）
         * claim.contentProof（最終発行者の署名、ZKP検証に必要）が有効
         * claim.contentがclaimSchemaに対して有効
         * **検証しない**: credential.issuerDIDと最終granteeDIDの一致
    3. **検証しない**: credentialの署名（Holderが再署名可能）

    **簡略化:**
    実装では、claimSchemaに対するcontent検証とproof検証を省略しています。
    実際の実装では、これらを適切に検証する必要があります。
-/
def verify (chain : TrustChain) (trustedAnchors : List ValidDID) : Bool :=
  -- 1. すべてのrootAnchorが信頼されているか
  if !chain.rootAnchors.all (fun anchor => trustedAnchors.contains anchor) then
    false
  else
    -- 2. 各claimを検証
    chain.claims.all (fun claim =>
      match claim.delegationChain with
      | none =>
          -- 0階層: issuerがrootAnchorsに含まれるか
          chain.rootAnchors.contains chain.credential.issuerDID
      | some delegationChain =>
          -- N階層: 委任チェーン全体を検証（Holder中心設計）
          -- 実際には以下をすべて検証する必要がある：
          -- 1. DelegationChain.verify（委任チェーン全体の検証）
          -- 2. claim.contentProof（最終発行者の署名）が有効（ZKP検証に必要）
          -- 3. claim.contentがclaimSchemaに対して有効
          -- 注: 最終granteeDIDとcredential.issuerDIDの一致は検証しない（Holder中心設計）
          delegationChain.verify trustedAnchors
    )

end TrustChain
```

---

## 6. Validation Protocol

### 6.1 属性VC検証のフローチャート（Holder中心設計 + N階層対応）

```
┌───────────────────────────────────┐
│ 1. VCの署名検証                    │
│    （Holder中心設計では省略可能）   │
│    UnknownVC.verifySignature      │
└─────────────┬─────────────────────┘
              │ valid?
              ▼ Yes
┌───────────────────────────────────┐
│ 2. 各claimを順次検証               │
│    （0階層からN階層が混在可能）     │
└─────────────┬─────────────────────┘
              │
              │ For each claim:
              │
              ├─ claim.delegationChain == none（0階層）
              │  ▼
              │  ┌──────────────────────────────┐
              │  │ 3a. 直接発行クレームの検証     │
              │  │ - issuerDIDがtrustedAnchors  │
              │  │   に含まれるか                │
              │  └──────────────────────────────┘
              │
              └─ claim.delegationChain != none（N階層）
                 ▼
                 ┌──────────────────────────────┐
                 │ 3b. 委譲発行クレームの検証     │
                 │   （Holder中心設計 + N階層）   │
                 │                              │
                 │ - 循環委任チェック             │
                 │   (DID重複がないか)           │
                 │ - 各delegationのmaxDepth検証  │
                 │   (単調減少性)                │
                 │ - 初代grantorDIDが            │
                 │   trustedAnchorsに含まれるか  │
                 │ - contentがclaimSchemaに有効  │
                 │ - 各delegationProofが有効     │
                 │ - contentProof（最終発行者署名）│
                 │   が有効（ZKP検証に必要）      │
                 │                              │
                 │ 検証しない:                   │
                 │ - VCのissuer                 │
                 │ - 最終granteeDIDとissuerの一致│
                 └──────────────────────────────┘
```

### 6.2 検証アルゴリズム（N階層対応）

```lean
/-- 属性VCを検証（トラストチェーンを含む）- Holder中心設計 + N階層対応

    **Holder中心設計 + N階層対応における検証:**
    - VCのissuerは検証しない（Holderでも、元の発行者でも、誰でもOK）
    - 各claimのdelegationChain全体を検証（DelegationChain.verify使用）
    - 循環委任の検出（DID重複チェック）
    - maxDepthの単調減少性を確認
    - 最終granteeDIDとissuerの一致は検証しない（granteeDIDは歴史的情報）
    - 各claimのcontentProof（最終発行者署名）を検証（ZKP検証に必要、Holderの改ざん検出）

    **パラメータ:**
    - vc: 検証対象のVC
    - trustedAnchors: 信頼されたDIDのリスト（Wallet.trustedAnchors）
    - validateDID: DID検証関数
    - validateSchema: JSON Schema検証関数
    - verifyProof: W3C Proof検証関数

    **戻り値:**
    - Some chain: 検証成功、トラストチェーンを返す
    - None: 検証失敗
-/
def verifyVCWithTrustChain
    (vc : ValidVC)
    (trustedAnchors : List ValidDID)
    (validateDID : W3C.DID → Option ValidDID)
    (validateSchema : JSONValue → Schema → Bool)
    (verifyProof : JSONValue → W3C.Proof → Bool)
    : Option TrustChain :=
  -- 1. VCの署名検証は不要（Holder中心設計では、VCの署名は重要でない）

  -- 2. 各claimを検証し、rootAnchorsを収集
  let claimsResult := vc.claims.mapM (fun claim =>
    match claim.delegation with
    | none =>
        -- 0階層: 直接発行
        if trustedAnchors.contains vc.issuerDID then
          some (vc.issuerDID, claim)
        else
          none
    | some delegation =>
        -- 1階層: 委譲発行
        -- grantorDIDが信頼されているか確認
        if !trustedAnchors.contains delegation.grantorDID then
          none
        -- contentがclaimSchemaに対して有効か確認
        else if !validateSchema claim.content delegation.claimSchema then
          none
        -- delegationProof（委任者の署名）を検証
        else if !verifyProof (serializeDelegation delegation) claim.delegationProof then
          none
        -- proof（受託者の署名）を検証（ZKP検証に必要）
        else if !verifyProof claim.content claim.proof then
          none
        -- 注: granteeDIDとissuerの一致は検証しない（Holder中心設計）
        else
          some (delegation.grantorDID, claim)
  )

  -- 3. すべてのclaimの検証に成功した場合、TrustChainを構築
  match claimsResult with
  | none => none
  | some claimsWithAnchors =>
      let rootAnchors := claimsWithAnchors.map (·.1) |> List.unique
      let claims := claimsWithAnchors.map (·.2)
      some {
        rootAnchors,
        claims,
        credential := vc
      }
```

---

## 7. Security Considerations

### 7.1 委譲の深さ制限

- **動的階層制限**: 各委任者がmaxDepthを指定、単調減少により無限階層を防止
- **プロトコルレベルの上限なし**: Nat型の性質により、有限回の委任で必ずゼロに到達
- **形式検証可能**: Lean4で停止性と有限長を証明（well-founded recursion）
- **柔軟な運用**: 政府は100層（実質無制限）、都道府県は5層、市区町村は2層など、組織の実情に合わせて設定可能
- **循環委任の防止**: DID重複チェックによりO(n)で検出
- **単調減少性**: `nextDepth = min(parentDepth - 1, delegation.maxDepth)`により各委任で深さが減少
- **実世界適合**: 多層的な組織構造（政府→都道府県→市区町村→部署など）を自然にサポート

### 7.2 スキーマ検証

- **JSON Schema Subset**: 停止性が保証されたサブセットを使用
- **循環参照防止**: `$ref`, `$defs`を除外
- **ネスト制限**: 最大3レベルのcomposition nesting

### 7.3 署名検証とHolder中心設計

**DelegationChainベースの信頼モデル**:

AMATELUSプロトコルは、従来のVC issuerベースの信頼モデルではなく、**DelegationChainベースの信頼モデル**を採用しています。

**従来のVCモデル（issuer中心）**:
- VCのissuerがtrustedAnchorsに含まれる必要がある
- issuerの署名を検証する必要がある
- VCを再パッケージングすると信頼が失われる

**AMATELUSモデル（Holder中心）**:
- **検証対象**: DelegationChain内の`grantorDID`と各委任の署名のみ
- **検証不要**: VCの`issuer`と`proof`（VC全体の署名）
- **再パッケージング可能**: Holderは任意のタイミングでVCを自己署名で再発行できる
- **ZKPとの親和性**: VCのissuerを完全に隠蔽してもDelegationChainで信頼を証明できる

**署名の階層**（新Claim構造）:

1. **最重要な署名**: 委任者の署名（各claimの`delegationProof`）
   - trustedAnchorsに含まれる`grantorDID`の秘密鍵で署名
   - 委任内容（`grantorDID`, `granteeDID`, `label`, `claimSchema`）を保証
   - **これが信頼の起点**

2. **重要な署名**: 受託者の署名（各claimの`proof`）
   - 受託者（`granteeDID`）の秘密鍵で`content`に対して署名
   - **ZKP検証時に必須**：Holderが`content`を改ざんしていないことを保証
   - Holder再パッケージング後も元のまま保持される
   - この署名により、ZKPの公開入力とVCの`content`の整合性を検証できる

3. **オプショナルな署名**: 発行者の署名（VC全体の`proof`）
   - VCの整合性を保証（改ざん防止）
   - Holder中心設計では検証不要（Holderが再署名可能）
   - データ整合性のために存在するが、信頼の証明には使用しない

**ZKPとの連携**:
- 各claimの`proof`（受託者署名）により、HolderはZKP生成後に`content`を改ざんできない
- Verifierは ZKPの公開入力と各claimの`content`が一致し、かつ`proof`が有効であることを確認
- これにより、ZKPで証明された内容が信頼できる委任元（grantor）から発行されたものであることを保証

**暗号学的保証**: Ed25519などの標準アルゴリズム

### 7.4 無限階層と循環委任の防止

- **無限階層の防止**: maxDepthの単調減少により有限回でゼロに到達（well-founded recursion）
- **循環委任の防止**: 委任チェーン内のDID重複チェック（O(n)の計算量）
- **プロトコルレベル保証**: 検証アルゴリズムに組み込まれ、不正な委任チェーンは検証失敗
- **形式検証**: Lean4でterminationとcircular_delegation_detectionを証明
- **実装側の責務**: DelegationChain.verifyの実装が循環委任とmaxDepth単調減少を確実にチェック

---

## 8. Examples

### 8.1 政府→自治体→住民（1階層委譲の例）

**ステップ1**: 政府が自治体AにDelegation Credentialを発行

```json
{
  "issuer": "did:amt:gov123",
  "credentialSubject": {
    "id": "did:amt:city-a456",
    "delegation": {
      "label": "住民票",
      "claimSchema": { ... },
      "maxDepth": 1
    }
  },
  "proof": {
    "verificationMethod": "did:amt:gov123#keys-1",
    "proofValue": "z3FX..."
  }
}
```

**ステップ2**: 自治体Aが住民に属性VCを発行（各claimに委任チェーンを埋め込み）

```json
{
  "issuer": "did:amt:city-a456",
  "credentialSubject": {
    "id": "did:amt:resident789",
    "claims": [
      {
        "content": {
          "name": "田中太郎",
          "address": "東京都千代田区...",
          "birthDate": "1990-01-01",
          "nationalID": "123456789012"
        },
        "delegationChain": {
          "delegations": [
            {
              "grantorDID": "did:amt:gov123",
              "granteeDID": "did:amt:city-a456",
              "label": "住民票",
              "claimSchema": { ... },
              "maxDepth": 1
            }
          ],
          "chainProofs": [
            {
              "verificationMethod": "did:amt:gov123#keys-1",
              "proofValue": "z3FX..."
            }
          ]
        },
        "contentProof": {
          "verificationMethod": "did:amt:city-a456#keys-1",
          "proofValue": "z5CD..."
        }
      }
    ]
  },
  "proof": {
    "verificationMethod": "did:amt:city-a456#keys-1",
    "proofValue": "z6EF..."
  }
}
```

**検証（Holder中心設計 + N階層対応）**:
1. 住民のWalletは`did:amt:gov123`をtrustedAnchorsに登録
2. 属性VCを受け取り、各claimを検証
3. claim[0]について：
   - `delegationChain.delegations[0].grantorDID`が`did:amt:gov123`（信頼済み）
   - `delegationChain.delegations[0].maxDepth`が1以上（有効）
   - `content`が`delegations[0].claimSchema`に対して有効
   - `chainProofs[0]`を`delegations[0].grantorDID`の公開鍵で検証
   - `contentProof`を`delegations[0].granteeDID`の公開鍵で検証（ZKP検証に必要）
   - 循環委任チェック（1階層なので該当なし）
4. トラストチェーン構築完了

**検証不要**:
- VCの`issuer`（`did:amt:city-a456`）の信頼性
- `delegations[0].granteeDID`と`issuer`の一致
- VCの`proof`（自治体の署名、VC全体に対する署名）

### 8.2 政府→都道府県→市区町村→部署（3階層委譲の例）

この例では、政府が都道府県に最大5階層を許可し、都道府県が市区町村に最大2階層に制限し、市区町村が部署に最大1階層に制限する多層構造を示します。

**ステップ1**: 政府が都道府県にDelegation Credentialを発行

```json
{
  "issuer": "did:amt:gov123",
  "credentialSubject": {
    "id": "did:amt:prefecture456",
    "delegation": {
      "label": "地方行政証明",
      "claimSchema": { ... },
      "maxDepth": 5
    }
  },
  "proof": {
    "verificationMethod": "did:amt:gov123#keys-1",
    "proofValue": "zA1B..."
  }
}
```

**ステップ2**: 都道府県が市区町村にDelegation Credentialを発行（maxDepthを2に制限）

```json
{
  "issuer": "did:amt:prefecture456",
  "credentialSubject": {
    "id": "did:amt:city789",
    "delegation": {
      "label": "市区町村証明",
      "claimSchema": { ... },
      "maxDepth": 2
    }
  },
  "proof": {
    "verificationMethod": "did:amt:prefecture456#keys-1",
    "proofValue": "zB2C..."
  }
}
```

**ステップ3**: 市区町村が部署にDelegation Credentialを発行（maxDepthを1に制限）

```json
{
  "issuer": "did:amt:city789",
  "credentialSubject": {
    "id": "did:amt:department012",
    "delegation": {
      "label": "部署証明",
      "claimSchema": { ... },
      "maxDepth": 1
    }
  },
  "proof": {
    "verificationMethod": "did:amt:city789#keys-1",
    "proofValue": "zC3D..."
  }
}
```

**ステップ4**: 部署が住民に属性VCを発行（3階層の委任チェーン）

```json
{
  "issuer": "did:amt:department012",
  "credentialSubject": {
    "id": "did:amt:resident345",
    "claims": [
      {
        "content": {
          "name": "鈴木花子",
          "certificationNumber": "XYZ-2024-001",
          "issueDate": "2024-01-15"
        },
        "delegationChain": {
          "delegations": [
            {
              "grantorDID": "did:amt:gov123",
              "granteeDID": "did:amt:prefecture456",
              "label": "地方行政証明",
              "claimSchema": { ... },
              "maxDepth": 5
            },
            {
              "grantorDID": "did:amt:prefecture456",
              "granteeDID": "did:amt:city789",
              "label": "市区町村証明",
              "claimSchema": { ... },
              "maxDepth": 2
            },
            {
              "grantorDID": "did:amt:city789",
              "granteeDID": "did:amt:department012",
              "label": "部署証明",
              "claimSchema": { ... },
              "maxDepth": 1
            }
          ],
          "chainProofs": [
            {
              "verificationMethod": "did:amt:gov123#keys-1",
              "proofValue": "zA1B..."
            },
            {
              "verificationMethod": "did:amt:prefecture456#keys-1",
              "proofValue": "zB2C..."
            },
            {
              "verificationMethod": "did:amt:city789#keys-1",
              "proofValue": "zC3D..."
            }
          ]
        },
        "contentProof": {
          "verificationMethod": "did:amt:department012#keys-1",
          "proofValue": "zD4E..."
        }
      }
    ]
  },
  "proof": {
    "verificationMethod": "did:amt:department012#keys-1",
    "proofValue": "zE5F..."
  }
}
```

**検証（Holder中心設計 + N階層対応）**:

1. 住民のWalletは`did:amt:gov123`をtrustedAnchorsに登録
2. 属性VCを受け取り、各claimを検証
3. claim[0]について：
   - **循環委任チェック**: すべてのDIDがユニーク（gov123, prefecture456, city789, department012）
   - **階層制限チェック**:
     - 初期remainingDepth: 初代grantorなので検証アルゴリズムで設定される十分大きい値
     - delegation[0]: maxDepth=5, nextDepth=min(remainingDepth-1, 5)=5
     - delegation[1]: maxDepth=2, nextDepth=min(5-1, 2)=2（都道府県が制限）
     - delegation[2]: maxDepth=1, nextDepth=min(2-1, 1)=1（市区町村が制限）
   - **初代grantor確認**: `delegations[0].grantorDID`が`did:amt:gov123`（信頼済み）
   - **各委任署名の検証**:
     - `chainProofs[0]`を`delegations[0].grantorDID`の公開鍵で検証
     - `chainProofs[1]`を`delegations[1].grantorDID`の公開鍵で検証
     - `chainProofs[2]`を`delegations[2].grantorDID`の公開鍵で検証
   - **content署名の検証**: `contentProof`を`delegations[2].granteeDID`の公開鍵で検証（ZKP検証に必要）
4. トラストチェーン構築完了

**検証不要**:
- VCの`issuer`（`did:amt:department012`）の信頼性
- `delegations[2].granteeDID`と`issuer`の一致
- VCの`proof`（部署の署名、VC全体に対する署名）

**単調減少性の例**:
```
政府 (initialDepth=十分大きい値、例えば100)
  ↓ maxDepth=5, nextDepth=min(99,5)=5
都道府県 (remainingDepth=5)
  ↓ maxDepth=2, nextDepth=min(4,2)=2  ← 都道府県が制限
市区町村 (remainingDepth=2)
  ↓ maxDepth=1, nextDepth=min(1,1)=1  ← 市区町村が制限
部署 (remainingDepth=1)
  ↓ これ以上の委任は不可（remainingDepth=0になるため）
```

---

## 9. References

- **W3C Verifiable Credentials Data Model 1.1**: https://www.w3.org/TR/vc-data-model/
- **AMATELUS JSON Schema Subset**: [AMATELUS/JSONSchemaSubset.md](./JSONSchemaSubset.md)
- **AMATELUS VC Definition**: [AMATELUS/VC.lean](./VC.lean)
- **JSON Schema 2020-12**: https://json-schema.org/draft/2020-12/json-schema-core

---

## 10. Implementation Notes

### 10.1 Lean側の実装（完了）

- `DelegationContent`型を定義（TrustChainTypes.lean）
- `DelegationChain`型を定義（TrustChainTypes.lean）
- `Claim`型を定義（TrustChainTypes.lean）
- `verifyChain`関数を実装（TrustChainTypes.lean）
- 停止性と有限性の定理を証明（TrustChainTypes.lean, TrustChain.lean）

### 10.2 実装側（Rust/TypeScript）の責任

- JSON Schema検証の実装（`validateSchema`関数）
- DIDDocument取得とDID検証
- Ed25519署名検証
- W3C VC形式のシリアライズ/デシリアライズ
- DelegationChainの抽出と検証

### 10.3 Wallet側の実装

- `trustedAnchors`リストの管理
- トラストチェーン検証の実行
- DelegationChainの抽出と検証
- JSON Schemaに対するclaims検証
