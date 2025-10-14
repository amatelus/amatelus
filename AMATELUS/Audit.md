# AMATELUS 監査メカニズム仕様

**Version**: 1.1
**Date**: 2025-10-14
**Base Document**: [匿名ハッシュ識別子論文](https://kuuga.io/papers/bafybeiewrf2fxsdbwz3vcc3jgleewubkwzdidutivlgkdrbs3n5z3kwpv4) (Version 2)

## 目次
1. [概要](#1-概要)
2. [アーキテクチャ](#2-アーキテクチャ)
3. [データ構造](#3-データ構造)
4. [監査フロー](#4-監査フロー)
5. [民間企業への応用](#5-民間企業への応用)
6. [金融機関への応用](#6-金融機関への応用)
7. [セキュリティ要件](#7-セキュリティ要件)
8. [プライバシー保護](#8-プライバシー保護)
9. [法的・制度的要件](#9-法的制度的要件)
10. [実装ガイドライン](#10-実装ガイドライン)
11. [形式検証](#11-形式検証)

---

## 1. 概要

本仕様は、AMATELUSプロトコルにおける**オプショナルな監査メカニズム**の技術仕様を定義します。**匿名ハッシュ識別子（AHI: Anonymous Hash Identifier）**は、監査が必要なサービスにおいてのみ使用され、市民のプライバシーを最大限保護しつつ、法的手続きに基づく必要な監査と責任追及を可能にします。

### 1.1 重要な前提条件

**AHIはオプショナル機能です。以下の条件を満たす場合にのみ使用されます：**

1. **IssuerまたはVerifierがAHIを要求する場合**
   - 監査が必要なサービス（納税、給付金、許認可等）
   - 多重アカウント防止が必要なサービス（SNS、チケット販売等）
   - 金融機関など法的にトレーサビリティが必要なサービス

2. **個人番号制度が存在する国・地域**
   - マイナンバー（日本）
   - Social Security Number（アメリカ）
   - その他の国民識別番号制度

**AHIを使用しない場合：**
- 通常のVCとZKPのみで十分なサービス
- 個人番号制度がない国・地域の市民
- IssuerやVerifierがAHIを要求しないサービス

### 1.2 背景と課題

従来の監査用DIDには以下の脆弱性がありました：

- **秘密鍵の意図的な紛失**: 市民が監査用DIDの秘密鍵を廃棄することで追跡を回避可能
- **名寄せの懸念**: 単一の監査用DIDを用いると、異なるサービス間で名寄せされる可能性

### 1.3 設計目標

- **オプショナリティ**: AHIはプロトコルの必須要素ではなく、必要なサービスでのみ使用
- **プライバシー保護**: 政府による国民情報の一元管理を回避
- **名寄せ防止**: サービス間の名寄せを技術的に防止
- **追跡回避の防止**: 監査が必要なサービスにおいて、不正行為者の意図的な追跡回避を不可能にする
- **法的整合性**: 裁判所の令状など既存の法的手続きに基づく監査を可能にする
- **グローバル対応**: 個人番号制度の有無に関わらずAMATELUSプロトコルを使用可能

---

## 2. アーキテクチャ

### 2.1 アクター

| アクター | 役割 | 責任 |
|---------|------|------|
| **市民** | サービス利用者 | ウォレットで匿名ハッシュ識別子を生成・管理、ZKP生成 |
| **自治体** | 世帯情報VC発行者 | 令状に基づくマイナンバー開示の実行 |
| **政府/監査機関** | 監査区分管理者 | 監査区分識別子の発行・公開、監査区分の定義 |
| **サービス提供者** | サービス提供者 | ZKP検証、匿名ハッシュ識別子の記録、不正検知 |
| **裁判所** | 法的手続き実行者 | 正当性審査、令状発行 |
| **関係機関** | 不正調査実施者 | 税務署、警察など、開示されたマイナンバーで調査 |

### 2.2 システム構成要素

```
┌─────────────┐
│   市民      │
│ ウォレット   │
│             │
│ ・世帯情報VC │
│ ・秘密鍵    │
│ ・ZKP生成   │
└──────┬──────┘
       │
       │ 匿名ハッシュ識別子 + ZKP
       ↓
┌─────────────────┐         ┌──────────────┐
│ サービス提供者   │←────────│ 政府レジストリ │
│                 │         │              │
│ ・ZKP検証       │         │ ・監査区分    │
│ ・ハッシュ記録  │         │  識別子公開   │
│ ・不正検知      │         └──────────────┘
└────────┬────────┘
         │ 不正報告
         ↓
┌─────────────┐
│  関係機関     │
│              │
│ ・開示請求    │
└──────┬───────┘
       │
       ↓
┌─────────────┐         ┌──────────────┐
│   裁判所     │         │   自治体      │
│              │         │              │
│ ・正当性審査 │─令状→│ ・マイナンバー │
│ ・令状発行   │         │  逆引き       │
└──────────────┘         │ ・開示        │
                          └──────────────┘
```

### 2.3 核心的なメカニズム

AHIを使用する監査メカニズムは3つの核心的な要素で構成されます：

1. **監査区分識別子**: 政府や監査機関が監査目的ごとに発行する公開識別子
2. **匿名ハッシュ識別子**: `Hash(監査区分識別子 || NationalID)`
3. **ゼロ知識証明**: ハッシュ生成の正当性を証明（NationalIDを開示せずに）

**重要**: これらの要素は、IssuerまたはVerifierが明示的にAHIを要求する場合にのみ使用されます。

### 2.4 国家識別システムの抽象化

AMATELUSプロトコルは、特定の国家識別システム（マイナンバー等）に依存しません。任意の国家識別システムに対応可能です：

```lean
-- Audit.lean より
structure NationalIDSystem where
  generate : Unit → NationalID
  validate : NationalID → Bool

-- プロトコルの一般適用可能性（定理）
theorem protocol_generality :
  ∀ (system : NationalIDSystem) (auditID : AuditSectionID),
    let nationalID := system.generate ()
    system.validate nationalID = true →
    ∃ (ahi : AnonymousHashIdentifier),
      ahi = AnonymousHashIdentifier.fromComponents auditID nationalID
```

**対応可能な識別システムの例:**
- マイナンバー（日本）
- Social Security Number（アメリカ）
- National Insurance Number（イギリス）
- その他の国民識別番号制度

**個人番号制度がない国:**
- AHI機能は使用できませんが、AMATELUSプロトコルの他の機能（VC、ZKP、DID等）は通常通り使用可能です

## 3. データ構造

### 3.1 監査区分識別子（Audit Category Identifier）

```lean
structure AuditCategoryId where
  id : String
  purpose : String              -- 例: "納税", "給付", "特定申請"
  issuer : ValidDID             -- 政府/監査機関のDID
  issuedAt : Nat                -- 発行日時
  deriving Repr, DecidableEq
```

**特性**:
- 政府が監査目的ごとに発行
- 公開レジストリで検証可能
- 一意性が保証される（UUID または ランダム文字列）
- 例: `"tax-2025"`, `"subsidy-education-2025"`, `"permit-building-tokyo"`

### 3.2 匿名ハッシュ識別子（Anonymous Hash Identifier）

```lean
def generateAnonymousHashId
    (categoryId : AuditCategoryId)
    (myNumber : String) : ByteArray :=
  -- PQC対応ハッシュ関数（SHA-3, BLAKE3等）
  Hash.pqcHash (categoryId.id ++ "||" ++ myNumber)
```

**数学的定義**:
```
AnonymousHashId = H(AuditCategoryId || MyNumber)

where:
  H: PQC対応ハッシュ関数
  ||: 連結演算子
```

**特性**:
- 耐量子計算機（PQC）対応のハッシュ関数を使用
- 監査区分ごとに異なる識別子が生成される（名寄せ防止）
- マイナンバーから逆算不可能（一方向性）
- 衝突耐性を持つ

### 3.3 国民識別番号VC（National ID Verifiable Credential）

**重要**: このVCは、AHI機能を使用する場合にのみ必要です。個人番号制度がない国や、AHIを使用しないサービスでは不要です。

```lean
-- VC.lean より
structure Claims where
  data : String  -- 実際には構造化データ
  claimID : Option ClaimID  -- クレームの識別子（Optionalに注意）
  deriving Repr, DecidableEq
```

国民識別番号（NationalID）を含むVCは、`Claims`の`data`フィールドに格納されます。

**JSON表現（マイナンバーを含む世帯情報VCの例）**:
```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "HouseholdCredential"],
  "issuer": "did:amatelus:city-hall-tokyo",
  "issuanceDate": "2025-10-14T00:00:00Z",
  "credentialSubject": {
    "id": "did:amatelus:citizen123...",
    "myNumber": "encrypted_my_number",
    "name": "田中太郎",
    "address": "東京都新宿区...",
    "birthDate": "1990-01-01"
  },
  "proof": {
    "type": "Dilithium2Signature2025",
    "created": "2025-10-14T00:00:00Z",
    "verificationMethod": "did:amatelus:city-hall-tokyo#key-1",
    "proofValue": "..."
  }
}
```

**重要な設計**:
- 国民識別番号（NationalID）は、VCの`data`フィールドに暗号化されて保管されます
- ウォレットは、AHI生成時にのみこのNationalIDを復号・使用します
- AHIを要求しないサービスでは、このVCやNationalIDは一切使用されません

### 3.4 ゼロ知識証明（Zero-Knowledge Proof）

```lean
structure AnonymousHashZKP where
  -- 公開入力
  publicInputs : {
    anonymousHashId : ByteArray        -- 匿名ハッシュ識別子
    categoryId : AuditCategoryId       -- 監査区分識別子
    vcIssuer : ValidDID                -- 世帯情報VCの発行者DID
  }
  -- 秘密入力（ZKP内部でのみ使用）
  witness : {
    myNumber : String                  -- マイナンバー
    householdVC : HouseholdVC          -- 世帯情報VC
    vcSignature : Signature            -- VCの署名
  }
  -- ZKP証明データ
  proof : ZKProof
  deriving Repr
```

**証明内容（ZKP回路内で検証）**:
1. `householdVC.proof`が有効（自治体が発行）
2. `myNumber`が`householdVC.credentialSubject.myNumber`と一致
3. `anonymousHashId = Hash(categoryId.id || myNumber)`が成立
4. `vcIssuer`が`householdVC.issuer`と一致

**形式的仕様**:
```lean
def verifyAnonymousHashZKP
    (zkp : AnonymousHashZKP) : Bool :=
  -- 1. ZKP証明の検証
  zkp.proof.verify zkp.publicInputs &&
  -- 2. 公開入力の整合性確認
  zkp.publicInputs.categoryId.issuer.isTrusted
```

## 4. 監査フロー

### 4.1 AHIを使用しない通常フロー（プライバシー保護モード）

**ほとんどのサービスでは、このフローで十分です。**

```
1. 市民 → サービス提供者
   - ZKPによる属性証明を提示
   - 個人情報（DID、氏名、NationalID）は非開示

2. サービス提供者
   - ZKPを検証
   - サービスを提供
```

#### シーケンス図

```
市民ウォレット              サービス提供者
    |                           |
    |--- ZKP（属性証明） ------→|
    |                           |
    |                           |--- ZKP検証
    |                           |
    |←------ サービス提供 -------|
```

**このフローでは:**
- NationalIDは一切使用されない
- 匿名ハッシュ識別子も使用されない
- 完全なプライバシー保護が実現される

### 4.1b AHIを使用するフロー（監査が必要なサービス）

**監査が必要なサービスでのみ、IssuerまたはVerifierがAHIを要求します。**

```
前提条件:
- サービス提供者が明示的にAHIを要求
- 市民が個人番号制度を持つ国・地域に居住
- 市民がNationalIDを含むVCを保持

1. 市民 → サービス提供者
   - ZKPによる属性証明を提示
   - 匿名ハッシュ識別子を提示
   - AHI正当性のZKPを提示

2. サービス提供者
   - ZKPを検証
   - AHI正当性を検証
   - 匿名ハッシュ識別子を記録
   - サービスを提供
```

#### シーケンス図

```
市民ウォレット              サービス提供者
    |                           |
    |--- ZKP + AHI + ZKP(AHI) →|
    |                           |
    |                           |--- ZKP検証
    |                           |--- AHI検証
    |                           |--- AHI記録
    |                           |
    |←------ サービス提供 -------|
```

**このフローでは:**
- NationalIDは依然として開示されない（ZKP内で秘密入力）
- AHIのみがサービス提供者に記録される
- サービス提供者は依然としてNationalIDを知ることができない

### 4.2 監査区分識別子の生成と公開（AHI使用時のみ）

**このステップは、監査が必要なサービスでのみ実行されます。**

```
1. 政府/監査機関または民間サービス提供者
   - 監査目的を定義（例: 納税、給付、特定申請、多重アカウント防止）
   - 監査区分識別子を生成（UUID等）
   - 識別子を公開レジストリに登録

2. サービス提供者（AHIを要求する場合）
   - 該当する監査区分識別子を取得
   - サービス利用時に市民に「AHIが必要」と通知
   - 監査区分識別子を市民ウォレットに提示
```

**例:**
- 政府サービス: `"tax-2025"`, `"subsidy-education-2025"`
- 民間サービス: `"sns-service-x"`, `"ticket-sales-y"`

**AHIを要求しないサービスでは、このステップは不要です。**

### 4.3 匿名ハッシュ識別子の生成フロー

```
1. 市民ウォレット
   - 世帯情報VCからマイナンバーを取得
   - 監査区分識別子を取得（政府公開レジストリから）
   - 匿名ハッシュ識別子を生成:
     Hash(監査区分識別子 || マイナンバー)

2. 市民ウォレット
   - ZKPを生成（ハッシュが正当に生成されたことを証明）
   - 証明内容:
     * 世帯情報VCが正規の自治体から発行されたもの
     * マイナンバーがVC内に含まれる
     * ハッシュが正しく計算されている

3. 市民 → サービス提供者
   - 匿名ハッシュ識別子を提示
   - ZKPを提示

4. サービス提供者
   - ZKPを検証
   - 匿名ハッシュ識別子を記録
```

#### シーケンス図

```
市民ウォレット      政府レジストリ    サービス提供者
    |                    |                  |
    |--- 監査区分識別子取得 →|                  |
    |←-- 識別子 ----------|                  |
    |                    |                  |
    |--- 世帯情報VCからマイナンバー取得        |
    |--- Hash計算 -------|                  |
    |--- ZKP生成 --------|                  |
    |                    |                  |
    |--- ハッシュ + ZKP ---------------→|
    |                    |                  |
    |                    |                  |--- ZKP検証
    |                    |                  |--- ハッシュ記録
    |                    |                  |
    |←------------ サービス提供 ------------|
```

### 4.4 不正調査・監査フロー

```
1. 不正の疑いの発生
   - サービス提供者が不正行為を検知
   - 該当する匿名ハッシュ識別子を特定

2. 法的手続き
   - サービス提供者 → 関係機関（警察等）
     * 不正内容と匿名ハッシュ識別子を報告

   - 関係機関 → 裁判所
     * 開示請求を申請

   - 裁判所
     * 正当性を審査
     * 令状を発行

3. マイナンバー開示
   - 裁判所 → 自治体
     * 令状を提示
     * 匿名ハッシュ識別子に対応するマイナンバーの開示を命令

   - 自治体
     * 令状の正当性を確認
     * 監査区分識別子を特定
     * 保有するマイナンバーデータベースから逆引き:
       For each マイナンバー in DB:
         if Hash(監査区分識別子 || マイナンバー) == 匿名ハッシュ識別子:
           該当するマイナンバーを特定
     * マイナンバーを関係機関に開示

4. 個人特定と調査
   - 関係機関
     * マイナンバーから個人を特定
     * 不正調査を実施
```

#### シーケンス図

```
サービス提供者  関係機関  裁判所  自治体
    |              |        |       |
    |--- 不正報告 →|        |       |
    |  (ハッシュ)   |        |       |
    |              |        |       |
    |              |--開示請求→|       |
    |              |        |       |
    |              |        |--令状発行→|
    |              |        |       |
    |              |        |       |---マイナンバー
    |              |        |       |   逆引き
    |              |        |       |
    |              |←-------令状に基づき---|
    |              |  マイナンバー開示  |
    |              |        |       |
    |---不正調査実施--|        |       |
```

## 5. 民間企業への応用（多重アカウント防止）

**重要**: この機能は、民間企業が明示的にAHIを要求する場合にのみ使用されます。

### 5.1 適用シナリオ

**AHIを要求する可能性がある民間サービス:**
- SNS（誹謗中傷・デマ拡散の防止）
- チケット販売（不正転売の防止）
- オンラインゲーム（多重アカウント防止）
- マーケットプレイス（詐欺防止）

**AHIを要求しない一般的なサービス:**
- 通常のEコマース
- 情報サイト
- 多重アカウントが問題にならないサービス

### 5.2 アカウント登録フロー（AHI使用時）

```
前提条件:
- 民間企業がAHIを要求することを決定
- 市民が個人番号制度を持つ国・地域に居住
- 市民がNationalIDを含むVCを保持

1. 民間企業（SNS、チケット販売等）
   - サービス固有識別子を生成・公開
   - アカウント登録画面で「AHI必須」と明示
   - 識別子を市民ウォレットに提示

2. 市民ウォレット
   - サービス固有識別子を受け取る
   - NationalID VCからNationalIDを取得
   - 匿名ハッシュ識別子を生成:
     Hash(サービス固有識別子 || NationalID)
   - ZKP(AHI)を生成

3. 市民 → 民間企業
   - 匿名ハッシュ識別子を提示
   - ZKP(AHI)を提示

4. 民間企業
   - ZKP(AHI)を検証
   - 自社DBで匿名ハッシュ識別子の重複をチェック
   - 重複なし → アカウント作成許可、ハッシュを記録
   - 重複あり → アカウント作成拒否（多重登録防止）
```

**個人番号制度がない国の市民:**
- AHIを提供できないため、これらのサービスを利用できない可能性がある
- サービス提供者は代替手段（例: 別の本人確認方法）を提供する必要がある

### 5.3 アカウント停止時の再登録防止

```
1. 不正行為によるアカウント停止
   - 民間企業が利用規約違反を検知
   - 該当アカウントを停止
   - 匿名ハッシュ識別子をブラックリストに追加

2. 再登録試行
   - 同一人物が新規アカウント作成を試行
   - 同じマイナンバー → 同じ匿名ハッシュ識別子が生成される
   - 民間企業がブラックリストと照合
   - 登録拒否

結果: 不正行為でアカウント停止された場合、同一サービスでの再登録が不可能
```

## 6. 金融機関への応用

**重要**: この機能は、法的にトレーサビリティが必要な金融サービスで使用されます。

### 6.1 適用シナリオ

**AHIを要求する金融サービス:**
- マネーロンダリング対策が必要な送金サービス
- 高額取引のトレーサビリティ確保
- 全銀システムなど金融機関横断のトレース

**AHIを要求しない可能性がある金融サービス:**
- 通常の預金口座（既存の本人確認で十分）
- 少額決済サービス

### 6.2 口座開設フロー（AHI使用時）

```
前提条件:
- 金融機関が法的にAHIを要求
- 顧客が個人番号制度を持つ国・地域に居住
- 顧客がNationalIDを含むVCを保持

1. 金融機関
   - 利用目的ごとの識別子を生成
   - 顧客に「AHI必須」と通知
   - 識別子を顧客ウォレットに配布

2. 顧客ウォレット
   - 識別子とNationalIDから匿名ハッシュ識別子を生成
   - ZKP(AHI)を生成

3. 金融機関
   - ZKP(AHI)を検証
   - 匿名ハッシュ識別子を顧客情報に紐付け
   - NationalIDは直接保管しない

4. 全銀システムでの応用
   - 匿名ハッシュ識別子による金融機関横断のトレース
   - マネーロンダリング対策
   - NationalID漏洩リスクの低減
```

**個人番号制度がない国の顧客:**
- AHIを提供できないため、代替の本人確認手段（パスポート番号等）が必要
- 各国の法規制に従った対応が必要

## 7. セキュリティ要件

### 7.1 ハッシュ関数

- **要件**: 耐量子計算機（PQC）対応
- **推奨**: SHA-3、BLAKE3等のPQC耐性を持つハッシュ関数
- **特性**:
  - 一方向性（プレイメージ耐性）
  - 衝突耐性
  - 第二プレイメージ耐性

### 7.2 ゼロ知識証明

- **要件**: PQC対応のZKPスキーム
- **証明内容**:
  - 世帯情報VCの正当性
  - マイナンバーの所有証明
  - ハッシュ計算の正当性
- **UX考慮**: 事前生成によるレスポンス時間の最小化

### 7.3 世帯情報VC管理

- **要件**:
  - ウォレット内で暗号化保管
  - マイナンバーの不正取得防止
  - VC発行者の署名検証

### 7.4 自治体のマイナンバー管理

- **要件**:
  - 令状の正当性検証
  - 逆引き処理のアクセスログ記録
  - 不正アクセス防止
  - データベースの暗号化

### 7.5 監査区分識別子の管理

- **要件**:
  - 識別子の一意性保証
  - 公開レジストリでの検証可能性
  - 識別子の悪用防止（レート制限等）

## 8. プライバシー保護

### 8.1 名寄せ防止

| シナリオ | 防止メカニズム |
|---------|--------------|
| 異なる行政サービス間 | 監査区分識別子が異なるため、ハッシュも異なる |
| 同一サービス内 | 同じハッシュが使われるが、他サービスと関連付け不可 |
| 民間企業間 | サービス固有識別子が異なるため、ハッシュも異なる |

### 8.2 マイナンバー非開示

- 市民はマイナンバーを直接提示しない
- サービス提供者はマイナンバーを知ることができない
- 自治体と監査機関以外はマイナンバーを扱わない

### 8.3 追跡回避の防止

- 市民が秘密鍵を紛失しても追跡可能（従来の監査用DIDの脆弱性を解消）
- 匿名ハッシュ識別子はマイナンバーから生成されるため、紛失や廃棄が不可能
- 不正行為者の意図的な追跡回避を技術的に防止

## 9. 法的・制度的要件

### 9.1 令状発行の基準

- 不正の合理的疑い
- 調査の必要性と比例性
- プライバシー侵害の最小化

### 9.2 開示手続きの透明性

- 令状発行の記録
- 自治体による開示実行の記録
- 市民への事後通知（法的に許容される範囲で）

### 9.3 社会的合意形成

- 監査が必要な場合の定義
- 監査区分の適切な設定
- マイナンバーの匿名ハッシュ識別子利用に関する法的解釈

## 10. 実装ガイドライン

### 10.1 ウォレットの実装

#### 10.1.1 必須機能

```lean
-- ウォレットが実装すべきインターフェース
class AuditWallet where
  -- 世帯情報VCの保管
  storeHouseholdVC : HouseholdVC → IO Unit

  -- 匿名ハッシュ識別子の生成
  generateHashId : AuditCategoryId → IO ByteArray

  -- ZKPの生成
  generateZKP : AuditCategoryId → IO AnonymousHashZKP

  -- マイナンバーの安全な保管（暗号化）
  secureStore : EncryptedData → IO Unit
```

#### 10.1.2 セキュリティ要件

- **マイナンバーの暗号化保管**: デバイスのセキュアストレージ（Keychain、TEE）を使用
- **ハッシュ生成の操作性**: ワンクリックで生成可能なUI
- **ZKP事前生成**: 事前生成によるレスポンス時間の最小化（UX向上）
- **監査履歴の記録**: いつ、どの監査区分で識別子を生成したかをローカルに記録

### 10.2 サービス提供者の実装

#### 10.2.1 データベース設計

```sql
-- 匿名ハッシュ識別子テーブル
CREATE TABLE anonymous_hash_identifiers (
  hash_id BYTEA PRIMARY KEY,
  audit_category_id VARCHAR(255) NOT NULL,
  first_seen_at TIMESTAMP NOT NULL,
  service_data JSONB,
  is_blacklisted BOOLEAN DEFAULT FALSE,
  INDEX idx_category (audit_category_id),
  INDEX idx_blacklist (is_blacklisted)
);
```

#### 10.2.2 ZKP検証の実装

```lean
def verifyServiceRequest
    (hashId : ByteArray)
    (zkp : AnonymousHashZKP)
    (categoryId : AuditCategoryId) : IO (Result ServiceToken) := do
  -- 1. ZKP検証
  if !verifyAnonymousHashZKP zkp then
    return .error "ZKP verification failed"

  -- 2. 監査区分の整合性確認
  if zkp.publicInputs.categoryId ≠ categoryId then
    return .error "Category mismatch"

  -- 3. 重複チェック
  if ← isDuplicate hashId then
    return .error "Duplicate registration"

  -- 4. ブラックリストチェック
  if ← isBlacklisted hashId then
    return .error "Blacklisted hash"

  -- 5. サービストークン発行
  issueServiceToken hashId
```

#### 10.2.3 パフォーマンス最適化

- **ZKP検証の並列化**: 複数のZKP検証を並列実行
- **キャッシュ戦略**: 検証済みZKPのキャッシュ（短時間）
- **インデックス最適化**: `hash_id`、`audit_category_id`、`is_blacklisted`にインデックス

### 10.3 自治体の実装

#### 10.3.1 逆引き処理の実装

```lean
def reverseLookup
    (hashId : ByteArray)
    (categoryId : AuditCategoryId)
    (warrant : Warrant) : IO (Option String) := do
  -- 1. 令状の正当性確認
  if !verifyWarrant warrant then
    return none

  -- 2. アクセスログ記録
  logAccess warrant hashId categoryId

  -- 3. マイナンバーデータベースで逆引き
  for myNumber in ← getAllMyNumbers do
    let computed := generateAnonymousHashId categoryId myNumber
    if computed = hashId then
      -- 4. 開示ログ記録
      logDisclosure myNumber hashId warrant
      return some myNumber

  return none
```

#### 10.3.2 セキュリティ要件

- **令状管理システム連携**: 令状の正当性をリアルタイムで検証
- **アクセスログの完全記録**: すべての逆引き処理を監査可能に記録
- **データベース暗号化**: マイナンバーデータベースの暗号化保管
- **アクセス制御**: 多要素認証、役割ベースアクセス制御（RBAC）

#### 10.3.3 スケーラビリティ

- **インデックス最適化**: マイナンバーへのハッシュインデックス事前計算
- **分散処理**: 大規模データベースの分散逆引き
- **キャッシュ戦略**: よく使われる監査区分のハッシュをキャッシュ

## 11. 形式検証

### 11.1 定理: 名寄せ不可能性

異なる監査区分では名寄せが技術的に不可能であることを証明：

```lean
theorem different_categories_prevent_linkability
    (myNumber : String)
    (cat1 cat2 : AuditCategoryId)
    (h : cat1.id ≠ cat2.id) :
  generateAnonymousHashId cat1 myNumber ≠
  generateAnonymousHashId cat2 myNumber := by
  -- ハッシュ関数の衝突耐性により、
  -- 入力が異なれば出力も異なる
  apply Hash.collision_resistance
  simp [generateAnonymousHashId]
  exact String.append_ne_of_prefix_ne h
```

**結果**: 同一人物が異なるサービスで生成した匿名ハッシュ識別子を関連付けることは計算量的に困難。

### 11.2 定理: 追跡回避の不可能性

マイナンバーから生成される識別子は意図的な廃棄が不可能：

```lean
theorem audit_always_possible
    (citizen : Citizen)
    (myNumber : String)
    (cat : AuditCategoryId)
    (h1 : citizen.householdVC.credentialSubject.myNumber = myNumber) :
  ∃ (hashId : ByteArray),
    hashId = generateAnonymousHashId cat myNumber ∧
    canReverseLookup hashId myNumber cat := by
  -- 自治体がマイナンバーデータベースを保持している限り、
  -- 匿名ハッシュ識別子から逆引き可能
  exists generateAnonymousHashId cat myNumber
  constructor
  · rfl
  · apply municipality_has_database
    exact h1
```

**結果**: 不正行為者が秘密鍵を廃棄しても、法的手続きに基づく追跡は可能。

### 11.3 定理: プライバシー保護

マイナンバーはZKPから推測不可能：

```lean
theorem zkp_preserves_privacy
    (zkp : AnonymousHashZKP)
    (adversary : Adversary) :
  computationallyInfeasible
    (adversary.extractMyNumber zkp) := by
  -- ZKPの知識健全性により、
  -- 証明からマイナンバーを抽出することは計算量的に困難
  apply ZKP.knowledge_soundness
  apply ZKP.zero_knowledge_property
```

**結果**: サービス提供者や第三者はマイナンバーを知ることができない。

### 11.4 定理: ハッシュ生成の正当性検証

ZKPはハッシュが正当に生成されたことを保証：

```lean
theorem zkp_guarantees_valid_hash
    (zkp : AnonymousHashZKP)
    (h : verifyAnonymousHashZKP zkp = true) :
  ∃ (myNumber : String) (vc : HouseholdVC),
    vc.proof.verify = true ∧
    zkp.publicInputs.anonymousHashId =
      generateAnonymousHashId zkp.publicInputs.categoryId myNumber := by
  -- ZKP検証が成功する場合、
  -- 必ず有効な世帯情報VCとマイナンバーが存在する
  apply ZKP.completeness
  exact h
```

**結果**: ZKP検証が成功した場合、必ず正規の自治体が発行した世帯情報VCに基づいている。

### 11.5 セキュリティ保証の数学的基盤

AMATELUSの監査メカニズムは以下の暗号学的仮定に基づきます：

| 特性 | 暗号学的仮定 | 保証レベル |
|------|-------------|----------|
| **名寄せ不可能性** | ハッシュ関数の衝突耐性 | 計算量的安全 |
| **追跡回避の防止** | 一方向性関数の性質 | 情報理論的安全 |
| **プライバシー保護** | ZKPの知識健全性 | 計算量的安全 |
| **ハッシュ正当性** | ZKPの完全性 | 数学的証明 |

---

## 12. 今後の課題

### 12.1 技術的課題

- **PQC ZKP技術の最適化**: 証明生成時間とサイズの削減
- **UX改善**: ハッシュ生成とZKP生成の操作性向上
- **スケーラビリティ**: 大規模な逆引き処理の効率化

### 12.2 制度的課題

- **社会合意形成**: 監査が必要な場合の明確な定義
- **法的整備**: 匿名ハッシュ識別子利用に関する法的解釈の確立
- **監査区分の設定**: 適切な粒度の監査区分設計

### 12.3 標準化

- **AMATELUSプロトコル仕様**: 詳細な技術仕様の策定
- **相互運用性**: 他のSSIシステムとの連携
- **国際標準化**: W3C、ISOなどでの標準化活動

---

## 付録A: 用語集

| 用語 | 説明 |
|------|------|
| AMATELUS | 自己主権型アイデンティティ（SSI）に基づく都市OSアーキテクチャ |
| DID | 分散型識別子（Decentralized Identifier） |
| VC | 検証可能なクレデンシャル（Verifiable Credential） |
| ZKP | ゼロ知識証明（Zero-Knowledge Proof） |
| PQC | 耐量子計算機（Post-Quantum Cryptography） |
| 監査区分識別子 | 政府が監査目的ごとに発行する識別子 |
| 匿名ハッシュ識別子 | 監査区分識別子とマイナンバーから生成されるハッシュ値 |
| 世帯情報VC | マイナンバーを含む世帯情報を格納したVC |
| 名寄せ | 複数の情報源から同一人物の情報を関連付けること |

## 付録B: 参考文献

### 学術論文・仕様書

- [AMATELUSとマイナンバーの併用で名寄せと不正行為の防止を両立させる匿名ハッシュ識別子](https://kuuga.io/papers/bafybeiewrf2fxsdbwz3vcc3jgleewubkwzdidutivlgkdrbs3n5z3kwpv4) (Version 2)
- [AMATELUS基盤のスマートシティにおける自治体窓口での本人認証と住民票・戸籍謄本VC発行方法](https://kuuga.io/papers/bafybeifchhu5nc2sckx4sekmmix3swgw4jbml7yyjorq3oewkzdfuibspq)

### AMATELUSプロトコル仕様

- [Trust Chain Specification](./TrustChain.md) - 委任チェーンと権限委譲
- [Key Management Specification](./KeyManagement.md) - 秘密鍵ライフサイクル管理
- [Multi-Device Support Specification](./MultiDevice.md) - マルチデバイス対応
- [Revocation Merkle Specification](./RevocationMerkle.md) - 失効管理

### W3C標準

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
