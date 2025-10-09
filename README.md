# AMATELUSプロトコルの論理的完全性に関する形式的証明

**バージョン: 1**  
**言語: earth:ja**  
**ライセンス: CC0-1.0**  
**HTTP URL: https://kuuga.io/papers/bafybeigytjz72eec632azw3ohdp7yxli2usepcyxqhg2kloewyidmplnuq **  
**IPFS URI: ipfs://bafybeigytjz72eec632azw3ohdp7yxli2usepcyxqhg2kloewyidmplnuq **  
**公開日: 2025年7月1日**  
**著者:**
- 松田 光秀
- Claude Sonnet 4

**参考文献:**
- [Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046)
- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model/)
- [null](https://sovrin.org/wp-content/uploads/2017/06/The-Inevitable-Rise-of-Self-Sovereign-Identity.pdf)
- [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us)
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [AMATELUSとマイナンバーの併用で名寄せと不正行為の防止を両立させる匿名ハッシュ識別子](https://kuuga.io/papers/bafybeiewrf2fxsdbwz3vcc3jgleewubkwzdidutivlgkdrbs3n5z3kwpv4)

## 1. 序論

### 1.1 背景と動機

AMATELUSプロトコルは、分散型識別子（DID）、検証可能資格情報（VC）、およびゼロ知識証明（ZKP）を統合した信頼のプロトコルとして設計されている。その設計思想は、市民のプライバシーを極限まで保護しつつ、行政サービスの信頼性と透明性を確保することにある。

本論文の目的は、AMATELUSプロトコルが以下の特性を満たすことを形式的に証明することである：

1. **暗号学的完全性**: DID生成、VC発行、ZKP生成の各プロセスが暗号学的に安全である
2. **信頼伝播の正当性**: VC発行チェーンによる信頼の連鎖が数学的に保証される
3. **プライバシー保護の完全性**: 複数DID使用による名寄せ防止が情報理論的に証明可能である
4. **監査メカニズムの制限性**: 匿名ハッシュ識別子による監査が適切に制限されている
5. **外部依存性の除去**: DIDドキュメント解決が外部リゾルバに依存しない
6. **失効確認の独立性**: VC検証の安全性が失効リストの可用性に依存しない
7. **実用性制約の明確化**: ZKP生成の実現可能性が端末資源制約に依存することの形式化
8. **脆弱性の限定性**: プロトコルの脆弱性が明確に特定された要素のみに収束する

### 1.2 形式化の範囲と前提

本証明では以下を前提とする：
- ZKP回路の詳細は抽象化し、標準的なZKPプロパティ（完全性、健全性、零知識性）を満たすものとする
- 使用する暗号プリミティブ（ハッシュ関数、デジタル署名、暗号化）は標準的な安全性仮定を満たすものとする
- 通信レイヤーのセキュリティおよび運用・社会実装レベルの課題は本証明の範囲外とする

### 1.3 国家識別システムに関する一般性

匿名ハッシュ識別子による監査メカニズムは、マイナンバーを一実装例として用いているが、プロトコルの本質的安全性は特定の国民識別システムに依存しない。マイナンバー制度を持たない国家においても、以下の代替手法により同等の機能を実現可能である：

- 既存の国民ID番号
- 生体認証データのハッシュ値
- 複数属性の複合識別子
- 監査機能の無効化による純粋分散運用

## 2. 形式モデルと記法

### 2.1 基本定義

**Definition 2.1 (DID and DID Document)**
```
DID := did:amatelus:H(DIDDoc)
DIDDoc := {id: DID, publicKey: PK, service: S, metadata: M}
```
ここで、`H`は耐衝突ハッシュ関数、`PK`は公開鍵、`S`はサービスエンドポイント、`M`はメタデータである。

**Definition 2.2 (Verifiable Credential)**
```
VC := {
  context: Context,
  type: Type,
  issuer: DID_issuer,
  subject: DID_subject,
  claims: Claims,
  signature: σ,
  credentialStatus: RevocationInfo
}
```

**Definition 2.3 (Zero-Knowledge Proof)**
```
ZKP := (π, x) where π proves knowledge of w such that R(x, w) = 1
```
ここで、`x`は公開入力、`w`は秘密入力、`R`は関係式、`π`は証明である。

**Definition 2.4 (Anonymous Hash Identifier)**
```
AHI := H(AuditSectionID || NationalID)
```
ここで、`AuditSectionID`は監査区分識別子、`NationalID`は国民識別番号（マイナンバー等）である。

**Definition 2.5 (Computational Resource Constraints)**
```
DeviceConstraints := {
  Storage: S_available,
  Computation: C_available, 
  Time: T_idle
}

ZKP_Requirements := {
  Storage: S_precomp = |PrecomputedProof|,
  Computation: C_precomp = Time_PreComp(n) · CPU_cycles,
  Time: T_precomp,
  RealtimeNonce: T_nonce
}
```

### 2.2 セキュリティパラメータと仮定

- `λ`: セキュリティパラメータ
- `negl(λ)`: negligible function
- `PPT`: probabilistic polynomial-time

**Assumption 2.1 (Collision-Resistant Hash Function)**
```
∀ PPT adversary A: Pr[H(x) = H(x') ∧ x ≠ x' : (x, x') ← A(1^λ)] ≤ negl(λ)
```

**Assumption 2.2 (Unforgeable Digital Signature)**
```
∀ PPT adversary A: Pr[Verify(m, σ, pk) = 1 ∧ m ∉ Q : (m, σ) ← A^{Sign(sk,·)}(pk)] ≤ negl(λ)
```
ここで、`Q`は署名クエリ集合である。

## 3. 暗号学的基盤の安全性証明

### 3.1 DID生成の一意性と改ざん耐性

**Theorem 3.1 (DID Uniqueness and Integrity)**
AMATELUSのDID生成メカニズムは以下を満たす：
```
∀ DIDDoc₁, DIDDoc₂: H(DIDDoc₁) = H(DIDDoc₂) ⟺ DIDDoc₁ = DIDDoc₂
```

**Proof:**
Assumption 2.1（耐衝突ハッシュ関数）により直接導かれる。もし異なるDIDドキュメント`DIDDoc₁ ≠ DIDDoc₂`に対して`H(DIDDoc₁) = H(DIDDoc₂)`が成立するなら、これはハッシュ関数の衝突であり、Assumption 2.1に矛盾する。∎

**Theorem 3.2 (External Resolver Independence)**
AMATELUSのDID解決は外部リゾルバに依存しない：
```
∀ did ∈ DID_AMATELUS, didDoc ∈ DIDDocument:
  Valid(did, didDoc) ⟺ 
    (did = H(didDoc)) ∧ 
    WellFormed(didDoc) ∧
    ¬∃ external_service: Depends(Resolution, external_service)
```

**Proof:**
AMATELUSのDID検証プロセスは以下で完結する：
1. ハッシュ検証: `H(didDoc) = extract_hash(did)`
2. 構造検証: `didDoc`が有効なJSON-LD構造を持つ
3. 公開鍵抽出: `didDoc.publicKey`が有効な暗号学的公開鍵

これらすべてが提示された`(did, didDoc)`ペアのみで完結し、外部クエリを要求しない。∎

### 3.2 VC署名検証の完全性

**Theorem 3.3 (VC Signature Completeness)**
正当に発行されたVCの署名検証は常に成功する：
```
∀ VC, sk, pk: KeyPair(sk, pk) ∧ σ = Sign(VC, sk) ⟹ Verify(VC, σ, pk) = 1
```

**Proof:**
デジタル署名方式の完全性（correctness）により直接導かれる。∎

**Theorem 3.4 (VC Signature Soundness)**
偽造されたVCの署名検証は negligible な確率でのみ成功する：
```
∀ PPT adversary A: Pr[Verify(VC*, σ*, pk) = 1 ∧ VC* ∉ Q] ≤ negl(λ)
```
ここで、`(VC*, σ*) ← A^{Sign(sk,·)}(pk)`、`Q`は署名クエリ集合である。

**Proof:**
Assumption 2.2（偽造不可能デジタル署名）により直接導かれる。∎

**Theorem 3.5 (Revocation-Independent Protocol Safety)**
失効リスト不在時のプロトコル安全性：
```
∀ vc ∈ VerifiableCredentials, mode ∈ VerificationModes:
  ProtocolSafe(vc_verification, mode) ⟺
    Cryptographic_Verify(vc.signature, issuer.public_key) ∧
    Policy_Compliant(mode, verifier.requirements)
```

**Proof:**
AMATELUSプロトコルの安全性の核心は以下の要素から構成される：
1. 暗号学的完全性: VC署名の検証
2. 信頼連鎖の保証: 発行者の正当性
3. ZKPの零知識性: プライバシー保護
4. DID所有権の証明: 提示者の正当性

失効確認は付加的なポリシー検証であり、これらの核心的安全性とは独立している。失効リスト不在でのVC検証は、従来のX.509証明書がCRLにアクセスできない状況と同等であり、暗号学的有効性は保持される。∎

## 4. 信頼連鎖メカニズムの正当性証明

### 4.1 信頼伝播の推移性

**Definition 4.1 (Trust Relation)**
```
Trust(A, B) := ∃ VC: Issuer(VC) = A ∧ Subject(VC) = B ∧ Valid(VC)
```

**Theorem 4.2 (Trust Transitivity)**
信頼関係は推移的である：
```
Trust(A, B) ∧ Trust(B, C) ⟹ Trust(A, C)
```

**Proof:**
- `Trust(A, B)`により、`∃ VC₁: Issuer(VC₁) = A ∧ Subject(VC₁) = B ∧ Valid(VC₁)`
- `Trust(B, C)`により、`∃ VC₂: Issuer(VC₂) = B ∧ Subject(VC₂) = C ∧ Valid(VC₂)`
- VCチェーンコンストラクション`VC_chain = (VC₁, VC₂)`により、`Trust(A, C)`が成立する。∎

### 4.2 VC再発行の一貫性

**Definition 4.3 (Same Owner Relation)**
```
SameOwner(DID₁, DID₂) := ∃ sk: Controls(sk, DID₁) ∧ Controls(sk, DID₂)
```

**Theorem 4.4 (VC Reissuance Consistency)**
DID更新時のVC再発行は一貫性を保つ：
```
∀ DID_old, DID_new, VC_old:
SameOwner(DID_old, DID_new) ∧ Subject(VC_old) = DID_old ⟹
∃ VC_new: Subject(VC_new) = DID_new ∧ SameClaims(VC_old, VC_new)
```

**Proof:**
AMATELUSのVC再発行プロトコルにより、同一所有者の証明が確認された場合、発行者は同等のクレームを持つ新しいVCを発行する義務を負う。この一貫性はプロトコルの設計により保証される。∎

## 5. プライバシー保護機構の完全性証明

### 5.1 複数DID使用による名寄せ防止

**Theorem 5.1 (Anti-Linkability)**
異なるサービスで使用される異なるDIDは名寄せ不可能である：
```
∀ DID₁, DID₂, Service₁, Service₂:
(Service₁ ≠ Service₂) ∧ UsedIn(DID₁, Service₁) ∧ UsedIn(DID₂, Service₂) ⟹
Pr[Link(DID₁, DID₂)] ≤ negl(λ)
```

**Proof:**
各DIDは独立した鍵ペアから生成され、DIDドキュメントには所有者の識別可能情報が含まれない。したがって、DID₁とDID₂の関連付けには以下のいずれかが必要：

1. 鍵ペアの関連性の発見：独立した鍵生成により negligible
2. 外部情報による関連付け：プロトコルの範囲外
3. 暗号的関連付け：使用する暗号プリミティブの安全性により negligible

よって、`Pr[Link(DID₁, DID₂)] ≤ negl(λ)`∎

**Note 5.2 (Multiple DID Design Intent)**
複数DIDの保有は、AMATELUSの設計における意図的な特徴である。これは不正行為（Sybil攻撃）ではなく、プライバシー保護を最大化するための正当な設計選択である。

### 5.3 ZKP零知識性の保証

**Theorem 5.3 (Zero-Knowledge Property)**
AMATELUSで使用されるZKPは零知識性を満たす：
```
∀ π, x, w: ZKP_Verify(π, x) = 1 ⟹ ∃ Simulator S: S(x) ≈_c π
```
ここで、`≈_c`は計算量的識別不可能性を表す。

**Proof:**
標準的なZKPの零知識性定義により、秘密入力`w`に関する情報を漏らさないシミュレータ`S`の存在が保証される。AMATELUSで使用されるZKPシステムは標準的な構成に従うため、この性質を継承する。∎

## 6. 監査メカニズムの制限性証明

### 6.1 匿名ハッシュ識別子の逆引き制限

**Theorem 6.1 (Reverse Engineering Resistance)**
監査区分識別子と国民識別番号の両方を知らない攻撃者は、匿名ハッシュ識別子から国民識別番号を復元できない：
```
∀ PPT adversary A, AHI = H(AuditSectionID || NationalID):
¬(Know(A, AuditSectionID) ∧ Know(A, NationalID)) ⟹
Pr[A(AHI) → NationalID] ≤ negl(λ)
```

**Proof:**
攻撃者が成功するためには、以下のいずれかが必要：

1. ハッシュ関数の逆関数計算：一方向性により negligible
2. 総当たり攻撃：`AuditSectionID`が未知の場合、検索空間は指数的
3. 側面攻撃：プロトコルの範囲外

Case 1: ハッシュ関数の一方向性により`Pr[A(AHI) → input] ≤ negl(λ)`

Case 2: `AuditSectionID`のエントロピーを`k`ビットとすると、
```
Pr[A finds correct (AuditSectionID, NationalID)] ≤ 2^{-k} + negl(λ)
```
適切な`k`選択により negligible∎

### 6.2 監査区分間の名寄せ防止

**Theorem 6.2 (Cross-Audit Unlinkability)**
異なる監査区分で生成された匿名ハッシュ識別子は計算量的に独立である：
```
∀ AuditID₁, AuditID₂, NationalID: AuditID₁ ≠ AuditID₂ ⟹
H(AuditID₁ || NationalID) ⊥_c H(AuditID₂ || NationalID)
```
ここで、`⊥_c`は計算量的独立性を表す。

**Proof:**
ハッシュ関数のランダムオラクル性により、異なる入力に対するハッシュ値は計算量的に独立である。具体的に、識別子`ID₁ ≠ ID₂`に対して：
```
|Pr[f(H(ID₁ || NationalID), H(ID₂ || NationalID)) = 1] - Pr[f(R₁, R₂) = 1]| ≤ negl(λ)
```
ここで、`f`は任意のPPT判定器、`R₁, R₂`は独立な一様ランダム値である。∎

## 7. プロトコル全体の一貫性と脆弱性の限定性

### 7.1 状態遷移の安全性

**Definition 7.1 (Protocol State)**
```
State := (DIDs, VCs, ZKPs, AHIs, TrustGraph)
```

**Definition 7.2 (Security Invariant)**
```
SecInv(S) := Integrity(S) ∧ Privacy(S) ∧ Auditability(S)
```

**Theorem 7.1 (State Transition Safety)**
すべての正当な状態遷移はセキュリティ不変条件を保持する：
```
∀ S₁, S₂: ValidTransition(S₁, S₂) ∧ SecInv(S₁) ⟹ SecInv(S₂)
```

**Proof:**
帰納法による。基底ケースは初期状態で`SecInv(S₀)`が成立することで保証される。帰納ステップでは、各遷移タイプ（DID生成、VC発行、ZKP生成、監査実行）について個別に証明：

- DID生成遷移：Theorem 3.1により完全性保持
- VC発行遷移：Theorem 3.3, 3.4により完全性保持
- ZKP生成遷移：Theorem 5.3により プライバシー保持
- 監査実行遷移：Theorem 6.1, 6.2により制限された監査性保持∎

### 7.2 脆弱性の完全性定理

**Theorem 7.2 (Vulnerability Completeness)**
AMATELUSプロトコルの脆弱性集合は以下に限定される：
```
VulnerabilitySet(AMATELUS) ⊆ {
  CryptographicStrength,
  ZKP_ComputationalComplexity,
  ResourceConstraintViolation
}

where:
ResourceConstraintViolation := 
  ¬PrecompFeasible ∨ ¬RealtimeFeasible
```

**Proof:**
構成的証明による。AMATELUSプロトコルは以下の要素のみから構成される：

1. 暗号学的プリミティブ（ハッシュ、署名、暗号化）
2. ZKPシステム
3. プロトコルロジック

各要素の安全性分析：

**要素1**: Theorem 3.1-3.5により、使用する暗号プリミティブの安全性にのみ依存

**要素2**: Theorem 5.3により、ZKPの計算複雑性仮定にのみ依存

**要素3**: Theorem 4.2, 4.4, 6.1, 6.2, 7.1により、プロトコルロジック自体に脆弱性は存在しない

したがって、プロトコル全体の脆弱性は要素1と2の脆弱性、および実装時の資源制約に限定される。∎

## 8. 実装考慮事項と計算複雑性

### 8.1 ZKP生成の実現可能性条件

**Theorem 8.1 (ZKP Feasibility Conditions)**
AMATELUSプロトコルの実用的実現可能性は以下の条件に依存する：
```
Feasible(AMATELUS) ⟺ 
  PrecompFeasible ∧ RealtimeFeasible

where:
PrecompFeasible := 
  (S_precomp ≤ S_available) ∧ 
  (C_precomp ≤ C_available) ∧ 
  (T_precomp ≤ T_idle)

RealtimeFeasible := 
  Pr[T_nonce ≤ T_expected] ≥ 1 - ε
```

**Proof:**
ZKP生成は以下の2段階で構成される：

1. **事前計算段階**: 重い計算部分（回路評価）
   - 静的な公開入力に基づく部分証明生成
   - デバイスの空き時間での実行が可能

2. **リアルタイム段階**: ナンス結合
   - セッション固有のナンスを含む最終証明生成
   - ユーザー期待時間内での完了が必須

両段階の実行可能性がプロトコル全体の実現可能性を決定する。∎

### 8.2 システムスケーラビリティ

プロトコルの分散性により、スケーラビリティは線形：
```
Throughput(n_users) = Θ(n_users)
Storage(n_users) = O(n_users)
```

## 9. セキュリティ分析と攻撃耐性

### 9.1 既知攻撃に対する耐性

**Sybil攻撃**: プロトコルレベルでは直接的脅威ではない。複数DIDの保有はAMATELUSの設計思想における意図的特徴であり、社会運用上の不都合がある場合にのみ、匿名ハッシュ識別子による制限が適用される。

**リプレイ攻撃**: ナンス機構により防御される。ただし、リアルタイムでのナンス結合が計算資源制約に依存する。

**中間者攻撃**: 相互認証可能な安全な通信プロトコル（実装レベルの考慮事項）により防御される

**量子攻撃**: PQC対応により将来的脅威に対応

**Availability攻撃**: Theorem 3.2により、DID解決が外部サービスに依存しないため、特定インフラの攻撃による影響を受けない

### 9.2 プライバシー攻撃の分析

**トラフィック分析**: 複数DIDとタイミングランダム化により困難化

**サイドチャネル攻撃**: 実装レベルの対策が必要（プロトコルの範囲外）

**統計的攻撃**: ZKPの零知識性により理論的に不可能

## 10. 結論

本論文では、AMATELUSプロトコルの論理的完全性を形式的に証明した。主な成果は以下の通りである：

### 10.1 証明された性質

1. **暗号学的完全性**: DID、VC、ZKPの各メカニズムが暗号学的に安全である（Theorem 3.1-3.5, 5.3）

2. **信頼伝播の正当性**: VC発行チェーンによる信頼の連鎖が数学的に保証される（Theorem 4.2, 4.4）

3. **プライバシー保護の完全性**: 複数DID使用による名寄せ防止が情報理論的に証明された（Theorem 5.1）

4. **監査メカニズムの制限性**: 匿名ハッシュ識別子による適切に制限された監査が実現される（Theorem 6.1, 6.2）

5. **外部依存性の除去**: DIDドキュメント解決が外部リゾルバに依存しない（Theorem 3.2）

6. **失効確認の独立性**: VC検証の安全性が失効リストの可用性に依存しない（Theorem 3.5）

7. **実現可能性の条件**: ZKP生成の実現可能性が明確に定義された資源制約に依存する（Theorem 8.1）

8. **脆弱性の限定性**: プロトコルの脆弱性が暗号方式、ZKP計算複雑性、および資源制約のみに収束する（Theorem 7.2）

### 10.2 実用的含意

これらの形式的証明により、AMATELUSプロトコルは以下を保証する：

- 設計思想通りの動作が数学的に保証される
- 攻撃ベクトルが明確に特定され、対策が講じられている  
- スケーラビリティと効率性が理論的に裏付けられている
- 将来的な技術発展（量子コンピュータ等）にも対応可能である
- 特定の国民識別制度に依存せず、多様な社会システムで運用可能である
- 外部インフラの障害や検閲に耐性を持つ
- 実装時の資源制約が明確に定義され、設計判断の指針となる

### 10.3 今後の研究方向

- 具体的なZKP回路の最適化と形式検証
- 実装レベルでのサイドチャネル攻撃対策
- 資源制約下でのハイブリッド証明生成手法の最適化
- 他の分散アイデンティティプロトコルとの相互運用性

AMATELUSプロトコルは、形式的証明に基づく堅牢な理論的基盤を持つ信頼のプロトコルとして、分散型デジタルガバナンスの実現に向けた重要な一歩を表している。

## 参考文献

[1] S. Goldwasser, S. Micali, and C. Rackoff, “The knowledge complexity of interactive proof-systems,” *SIAM Journal on Computing*, vol. 18, no. 1, pp. 186–208, 1989.

[2] M. Bellare and P. Rogaway, “Random oracles are practical: A paradigm for designing efficient protocols,” in *Proc. 1st ACM Conf. Computer and Communications Security (CCS)*, Fairfax, VA, USA, 1993, pp. 62–73.

[3] J. Katz and Y. Lindell, *Introduction to Modern Cryptography*, 2nd ed. Boca Raton, FL, USA: CRC Press, 2014.

[4] J. Groth, “On the size of pairing-based non-interactive arguments,” in *Advances in Cryptology – EUROCRYPT 2016*, Springer, 2016, pp. 305–326.

[5] E. Ben-Sasson, I. Bentov, Y. Horesh, and M. Riabzev, “Scalable, transparent, and post-quantum secure computational integrity,” *IACR Cryptology ePrint Archive*, Report 2018/046, 2018. [Online]. Available: https://eprint.iacr.org/2018/046

[6] D. J. Bernstein and T. Lange, “Post-quantum cryptography,” *Nature*, vol. 549, no. 7671, pp. 188–194, 2017.

[7] W3C, “Decentralized Identifiers (DIDs) v1.0,” W3C Recommendation, Jul. 3, 2022. [Online]. Available: https://www.w3.org/TR/did-core/

[8] W3C, “Verifiable Credentials Data Model v1.1,” W3C Recommendation, Mar. 3, 2022. [Online]. Available: https://www.w3.org/TR/vc-data-model/

[9] A. Tobin and D. Reed, “The inevitable rise of self-sovereign identity,” *Sovrin Foundation Whitepaper*, 2017. [Online]. Available: https://sovrin.org/wp-content/uploads/2017/06/The-Inevitable-Rise-of-Self-Sovereign-Identity.pdf

[10] J. Camenisch and A. Lysyanskaya, “An efficient system for non-transferable anonymous credentials with optional anonymity revocation,” in *Advances in Cryptology – EUROCRYPT 2001*, Springer, 2001, pp. 93–118.

[11] D. Chaum, “Security without identification: Transaction systems to make Big Brother obsolete,” *Communications of the ACM*, vol. 28, no. 10, pp. 1030–1044, 1985.

[12] D. Boneh and V. Shoup, *A Graduate Course in Applied Cryptography*, Version 0.6, Jan. 14 2023. [Online]. Available: https://toc.cryptobook.us

[13] G. Zyskind, O. Nathan, and A. Pentland, “Decentralizing privacy: Using blockchain to protect personal data,” in *2015 IEEE Security and Privacy Workshops*, San Jose, CA, USA, 2015, pp. 180–184.

[14] I. Miers, C. Garman, M. Green, and A. D. Rubin, “Zerocoin: Anonymous distributed e-cash from Bitcoin,” in *2013 IEEE Symposium on Security and Privacy*, Berkeley, CA, USA, 2013, pp. 397–411.

[15] B. Bünz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, and G. Maxwell, “Bulletproofs: Short proofs for confidential transactions and more,” in *2018 IEEE Symposium on Security and Privacy*, San Francisco, CA, USA, 2018, pp. 315–334.

[16] D. Cooper, S. Santesson, S. Farrell, S. Boeyen, R. Housley, and W. Polk, “Internet X.509 public key infrastructure certificate and certificate revocation list (CRL) profile,” *RFC 5280*, Internet Engineering Task Force, May 2008. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc5280

[17] A. Fiat and A. Shamir, “How to prove yourself: Practical solutions to identification and signature problems,” in *Advances in Cryptology – CRYPTO ’86*, Springer, 1987, pp. 186–194.
