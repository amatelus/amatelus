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
