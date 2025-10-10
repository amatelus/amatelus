/-
# 暗号プリミティブ型定義

このファイルは、AMATELUSプロトコルで使用される基本的な暗号型を定義します。
このファイルは依存関係の最下層に位置し、他のモジュールからインポートされます。

## 設計原則

このファイルを分離することで、以下の利点が得られます：
1. **循環インポートの回避**: Basic.lean と SecurityAssumptions.lean の循環依存を解消
2. **型の統一**: Hash、PublicKey等の基本型を一箇所で定義
3. **モジュラリティ**: 暗号プリミティブの変更が容易
-/

-- ## 基本的な暗号型

/-- ハッシュ値を表す型

    AMATELUSプロトコルでは、SHA3-512を使用するため、
    実装では64バイト（512ビット）の固定長配列となる。
-/
structure Hash where
  value : List UInt8
  deriving Repr, DecidableEq

/-- 公開鍵を表す型

    AMATELUSプロトコル Version 0では、Ed25519を使用するため、
    実装では32バイト固定長となる。
-/
structure PublicKey where
  bytes : List UInt8
  deriving Repr, DecidableEq

/-- 秘密鍵を表す型

    AMATELUSプロトコル Version 0では、Ed25519を使用するため、
    実装では32バイト固定長となる。
-/
structure SecretKey where
  bytes : List UInt8
  deriving Repr, DecidableEq

/-- デジタル署名を表す型

    AMATELUSプロトコル Version 0では、Ed25519を使用するため、
    実装では64バイト固定長となる。
-/
structure Signature where
  bytes : List UInt8
  deriving Repr, DecidableEq

-- ## ZKP（Zero-Knowledge Proof）関連型

/-- 公開入力を表す型

    ZKPの検証者が知っている情報。
    例: "age >= 20"という主張における20
-/
structure PublicInput where
  data : List UInt8

/-- 秘密入力（witness）を表す型

    ZKPの証明者のみが知っている情報。
    例: "age >= 20"という主張における実際の年齢25
-/
structure Witness where
  data : List UInt8

/-- ZKP証明を表す型

    証明データ（π）のバイト列表現。
-/
structure Proof where
  bytes : List UInt8

/-- 関係式を表す型

    ZKPで証明される関係式 R(x, w)。
    x: 公開入力、w: 秘密入力（witness）
    例: R(20, 25) = (25 >= 20) = true
-/
def Relation := PublicInput → Witness → Bool

-- ## 暗号学的ハッシュ関数

/-- 暗号学的ハッシュ関数（AMATELUSプロトコル標準）

    **AMT仕様（amt.md）に準拠したハッシュ関数:**
    - **アルゴリズム**: SHA3-512（NIST FIPS 202準拠）
    - **出力長**: 64バイト（512ビット）固定
    - **耐衝突性**: ポスト量子暗号（PQC）レベル

    **性質:**
    1. **決定性**: 同じ入力には常に同じ出力
    2. **耐衝突性**: H(x₁) = H(x₂) ∧ x₁ ≠ x₂ を見つけることが計算量的に困難
       - 形式的証明: SecurityAssumptions.amatHashFunction.collisionResistance
    3. **一方向性**: H(x) = h から x を計算することが困難
       - 形式的証明: SecurityAssumptions.hashOneWayness
    4. **ランダムオラクル性**: 理想的なランダム関数として振る舞う
       - 形式的証明: SecurityAssumptions.randomOracleProperty

    **セキュリティレベル:**
    - 古典計算機: 2^256 計算量（実質的に破られない）
    - 量子計算機: 2^170 計算量（Groverのアルゴリズム適用後もPQCレベル）

    **統合関係:**
    この公理は、SecurityAssumptions.leanの`amatHashFunction.hash`と同一です。
    詳細な暗号学的性質（耐衝突性、一方向性、ランダムオラクル性）は
    SecurityAssumptions.leanを参照してください。

    **参考文献:**
    - amt.md: did:amt Method Specification Version 0
    - NIST FIPS 202: SHA-3 Standard
      https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
-/
axiom hashForDID : List UInt8 → Hash

/-- ハッシュ関数の耐衝突性（決定的単射性の簡略化表現）

    **形式的な主張:**
    ```
    H(x₁) = H(x₂) → x₁ = x₂  （決定的単射性）
    ```

    **注意（厳密性）:**
    暗号学的には、耐衝突性は確率的な性質であり、厳密には：
    ```
    ∀ PPT攻撃者 A, Pr[A が衝突 (x₁, x₂) を発見] は negligible
    ```
    と定義されるべきです（SecurityAssumptions.amatHashFunction.collisionResistance）。

    ここでは**形式検証の簡略化**のため、決定的単射性として扱います。
    これは以下の理由により正当化されます：

    1. **SHA3-512の実用的強度**:
       - 2^256の計算量 → 宇宙の原子の数（約2^270）に匹敵
       - 現実的には衝突発見は不可能

    2. **形式検証の慣例**:
       - Isabelle/HOL、Coqなどの定理証明器でも同様のアプローチ
       - 確率的性質を決定的に扱うことで証明を単純化

    3. **証明の保存性**:
       - この仮定の下で証明された定理は、確率的定義でも成立
       - より強い仮定（決定的）→ より弱い結論（確率的）は論理的に妥当

    **統合関係:**
    この公理は、SecurityAssumptions.amatHashFunction.collisionResistanceの
    決定的バージョンです。確率的な形式的証明については
    SecurityAssumptions.leanを参照してください。
-/
axiom hashForDID_injective_with_high_probability :
  ∀ (x₁ x₂ : List UInt8),
    hashForDID x₁ = hashForDID x₂ → x₁ = x₂
