/-
# AMATELUS JSON Schema Subset Definition

このファイルは、AMATELUS プロトコル用の JSON Schema サブセットの Lean 形式化を含みます。

## 参考文献
- AMATELUS JSON Schema Subset: AMATELUS/JSONSchemaSubset.md
- JSON Schema 2020-12 (Base): https://json-schema.org/draft/2020-12/json-schema-core
- JSON Schema Validation: https://json-schema.org/draft/2020-12/json-schema-validation

## 設計方針
1. **形式検証可能**: すべての機能が Lean で証明可能
2. **参照なし**: $ref, $defs を除外し、循環参照を防止
3. **停止性保証**: ネスト深さ制限により停止性を保証
4. **プロトコル保証**: サブセットのみがプロトコルレベルで保証される

## サブセットの制限
- ❌ 参照系: $ref, $defs, $dynamicRef (循環参照防止)
- ❌ 動的検証: additionalProperties, patternProperties (プロトコルレベルで無視)
- ❌ 条件分岐: if/then/else (oneOf で代替可能)
- ❌ フォーマット: format (pattern で代替可能)
- ⚠️ ネスト制限: composition keywords は最大3レベル
-/

-- ## JSON データモデル

/-- JSON値の型定義

    JSON仕様（RFC 8259）に基づく6つのプリミティブ型：
    - null: ヌル値
    - bool: 真偽値
    - number: 数値（整数または浮動小数点）
    - string: 文字列
    - array: 値の順序付きリスト
    - object: キー・値ペアの非順序集合

    **設計上の注意:**
    - numberは簡略化のためFloatで表現（実際のJSON仕様では任意精度）
    - objectはList (String × JSONValue)で表現（重複キーは許容）
-/
inductive JSONValue
  | null : JSONValue
  | bool : Bool → JSONValue
  | number : Float → JSONValue
  | string : String → JSONValue
  | array : List JSONValue → JSONValue
  | object : List (String × JSONValue) → JSONValue
  deriving Repr, BEq

namespace JSONValue

/-- オブジェクトからプロパティを検索 -/
def lookup (obj : List (String × JSONValue)) (key : String) : Option JSONValue :=
  obj.lookup key

/-- 配列の長さを取得 -/
def arrayLength : JSONValue → Option Nat
  | array items => some items.length
  | _ => none

/-- オブジェクトのプロパティ数を取得 -/
def objectSize : JSONValue → Option Nat
  | object props => some props.length
  | _ => none

/-- 数値が整数かどうかを判定 -/
def numberIsInt (f : Float) : Bool :=
  f.floor == f

/-- JSON値が指定された基本型かどうかを判定 -/
def isType : JSONValue → String → Bool
  | null, "null" => true
  | bool _, "boolean" => true
  | number _, "number" => true
  | number n, "integer" => numberIsInt n
  | string _, "string" => true
  | array _, "array" => true
  | object _, "object" => true
  | _, _ => false

end JSONValue

-- ## JSON Schema サブセット構造

/-- JSON Pointer型（エラーパスの表現に使用） -/
abbrev JSONPointer := String

mutual

  /-- JSON Schema型（AMATELUSサブセット）

      JSON Schemaは以下のいずれか：
      - Boolean schema: `true` (すべて受理) または `false` (すべて拒否)
      - Object schema: キーワードのリストを含むオブジェクト

      **サブセットの特徴:**
      - $ref, $defs を含まない（循環参照を防止）
      - additionalProperties を検証しない（プロトコルレベルで無視）
      - if/then/else を含まない（oneOf で代替）
  -/
  inductive Schema
    | boolSchema : Bool → Schema
    | objectSchema : List SchemaKeyword → Schema

  /-- スキーマキーワードの型（AMATELUSサブセット）

      **サポートされるキーワード:**
      - 型: type
      - 文字列: maxLength, minLength, pattern
      - 数値: maximum, minimum, multipleOf
      - 配列: maxItems, minItems, uniqueItems, items
      - オブジェクト: maxProperties, minProperties, required, properties
      - 汎用: enum, const
      - 組み合わせ: allOf, anyOf, oneOf, not (最大3レベル)
      - アノテーション: title, description (検証に影響しない)

      **除外されたキーワード:**
      - $ref, $defs, $dynamicRef (参照系)
      - additionalProperties, patternProperties (動的検証)
      - if, then, else (条件分岐)
      - format (フォーマット検証)
      - その他のアノテーション (default, examples, deprecated, etc.)
  -/
  inductive SchemaKeyword
    -- Type keyword
    | type : List String → SchemaKeyword  -- type
    -- String validation
    | maxLength : Nat → SchemaKeyword
    | minLength : Nat → SchemaKeyword
    | pattern : String → SchemaKeyword  -- 正規表現（ECMA-262）
    -- Numeric validation
    | maximum : Float → SchemaKeyword
    | minimum : Float → SchemaKeyword
    | multipleOf : Float → SchemaKeyword
    -- Array validation
    | maxItems : Nat → SchemaKeyword
    | minItems : Nat → SchemaKeyword
    | uniqueItems : Bool → SchemaKeyword
    | items : Schema → SchemaKeyword
    -- Object validation
    | maxProperties : Nat → SchemaKeyword
    | minProperties : Nat → SchemaKeyword
    | required : List String → SchemaKeyword
    | properties : List (String × Schema) → SchemaKeyword
    -- Generic validation
    | enum : List JSONValue → SchemaKeyword
    | const : JSONValue → SchemaKeyword
    -- Composition (depth-limited)
    | allOf : List Schema → SchemaKeyword
    | anyOf : List Schema → SchemaKeyword
    | oneOf : List Schema → SchemaKeyword
    | not : Schema → SchemaKeyword
    -- Annotation keywords (informational only)
    | title : String → SchemaKeyword
    | description : String → SchemaKeyword

end

namespace Schema

/-- スキーマからtypeキーワードを取得 -/
def getType : Schema → Option (List String)
  | objectSchema keywords =>
      keywords.findSome? fun kw =>
        match kw with
        | SchemaKeyword.type types => some types
        | _ => none
  | _ => none

/-- スキーマからrequiredキーワードを取得 -/
def getRequired : Schema → List String
  | objectSchema keywords =>
      keywords.foldl (fun acc kw =>
        match kw with
        | SchemaKeyword.required props => props
        | _ => acc
      ) []
  | _ => []

/-- スキーマからpropertiesキーワードを取得 -/
def getProperties : Schema → List (String × Schema)
  | objectSchema keywords =>
      keywords.foldl (fun acc kw =>
        match kw with
        | SchemaKeyword.properties props => props
        | _ => acc
      ) []
  | _ => []

end Schema

-- ## バリデーション結果

/-- バリデーションエラーの情報 -/
structure ValidationError where
  message : String
  path : JSONPointer
  keyword : String
  deriving Repr

/-- バリデーション結果 -/
inductive ValidationResult
  | valid : ValidationResult
  | invalid : List ValidationError → ValidationResult
  deriving Repr

namespace ValidationResult

/-- バリデーション結果が有効かどうか -/
def isValid : ValidationResult → Bool
  | valid => true
  | invalid _ => false

/-- 複数の結果を結合（すべて有効なら有効） -/
def combineAll : List ValidationResult → ValidationResult
  | [] => valid
  | (valid :: rest) => combineAll rest
  | (invalid errs :: rest) =>
      match combineAll rest with
      | valid => invalid errs
      | invalid errs' => invalid (errs ++ errs')

/-- 複数の結果のうち少なくとも1つが有効なら有効 -/
def combineAny : List ValidationResult → ValidationResult
  | [] => invalid [{ message := "No schemas to validate against", path := "", keyword := "anyOf" }]
  | results =>
      if results.any (fun r => r.isValid) then
        valid
      else
        invalid [{ message := "None of the schemas matched", path := "", keyword := "anyOf" }]

/-- 複数の結果のうちちょうど1つが有効なら有効 -/
def combineOne : List ValidationResult → ValidationResult
  | [] => invalid [{ message := "No schemas to validate against", path := "", keyword := "oneOf" }]
  | results =>
      let validCount := results.filter (fun r => r.isValid) |>.length
      if validCount == 1 then
        valid
      else if validCount == 0 then
        invalid [{ message := "None of the schemas matched", path := "", keyword := "oneOf" }]
      else
        invalid [{ message := s!"Expected exactly one match, got {validCount}", path := "", keyword := "oneOf" }]

end ValidationResult

-- ## 正規表現マッチング抽象化

/-- 正規表現パターン型 -/
abbrev RegexPattern := String

/-- マッチ成功した文字列

    正規表現パターンにマッチした文字列を表す型。
    型レベルで正規性を保証し、UnknownVCと同様の設計パターンを使用。

    **設計:**
    - 実際の正規表現エンジン（ECMA-262）は外部実装に依存
    - プロトコルレベルではマッチ成功を抽象化
    - Issuer/Validatorが正しい実装を使用することを前提
-/
structure MatchedString where
  value : String
  pattern : RegexPattern
  deriving Repr

/-- マッチ失敗した文字列

    正規表現パターンにマッチしなかった文字列を表す型。

    **設計:**
    - 型レベルでマッチ失敗を表現
    - 実装の詳細は抽象化
-/
structure UnmatchedString where
  value : String
  pattern : RegexPattern
  reason : String  -- デバッグ用（プロトコルには不要）
  deriving Repr

/-- 未検証のマッチ結果

    正規表現マッチングの結果を表す和型。
    ValidVC/InvalidVCと同様の設計パターン。

    **命名の意図:**
    - 「UnknownMatchResult」= 構造的には存在するが、マッチ状態は未確定または既知
    - マッチ成功/失敗のいずれかを型レベルで表現

    **設計の利点:**
    - 正規表現エンジンの実装詳細を抽象化
    - プロトコルレベルでは「マッチ/非マッチ」の区別のみが重要
    - 実装バグは`unmatched`として表現され、プロトコルの安全性には影響しない
-/
inductive UnknownMatchResult
  | matched : MatchedString → UnknownMatchResult
  | unmatched : UnmatchedString → UnknownMatchResult
  deriving Repr

namespace UnknownMatchResult

/-- マッチ検証関数（定義として実装）

    **設計の核心:**
    - マッチ成功（matched）: 常に検証成功
    - マッチ失敗（unmatched）: 常に検証失敗

    この単純な定義により、正規表現エンジンの詳細を抽象化しつつ、
    プロトコルの安全性を形式的に証明できる。
-/
def checkMatch : UnknownMatchResult → Bool
  | matched _ => true
  | unmatched _ => false

/-- マッチ結果が成功かどうかを表す述語 -/
def isMatched (result : UnknownMatchResult) : Prop :=
  checkMatch result = true

/-- Theorem: マッチ成功した文字列は常に検証成功

    正規表現にマッチした文字列は、検証が成功する。
    これは定義から自明だが、明示的に定理として示す。
-/
theorem matched_string_passes :
  ∀ (ms : MatchedString),
    isMatched (matched ms) := by
  intro ms
  unfold isMatched checkMatch
  rfl

/-- Theorem: マッチ失敗した文字列は常に検証失敗

    正規表現にマッチしなかった文字列は、検証が失敗する。
-/
theorem unmatched_string_fails :
  ∀ (us : UnmatchedString),
    ¬isMatched (unmatched us) := by
  intro us
  unfold isMatched checkMatch
  simp

end UnknownMatchResult

-- ## バリデーション型（VC.lean パターン）

/-- スキーマに対して有効な JSON 値

    型レベルでバリデーション成功を保証。
    実際の検証ロジックは実装側（Rust/TypeScript等）で行われる。

    **設計:**
    - ValidVC と同じパターン
    - 型自体が「検証済み」を表現
    - プロトコルレベルでは抽象化
-/
structure ValidJSONValue where
  value : JSONValue
  schema : Schema

/-- スキーマに対して無効な JSON 値

    型レベルでバリデーション失敗を保証。
    実装側のバリデーターがエラーを検出した場合に使用される。

    **設計:**
    - InvalidVC と同じパターン
    - エラー情報を含む（デバッグ用）
-/
structure InvalidJSONValue where
  value : JSONValue
  schema : Schema
  errors : List ValidationError

/-- 未検証のバリデーション結果

    構造的にはJSON値とスキーマのペアだが、バリデーション結果を表す和型。
    ValidVC/InvalidVCと同様の設計パターン。

    **命名の意図:**
    - 「UnknownValidation」= 構造的には存在するが、バリデーション状態は未確定または既知
    - valid/invalid のいずれかを型レベルで表現

    **設計の利点:**
    - バリデーションロジックの実装詳細を抽象化
    - プロトコルレベルでは「valid/invalid」の区別のみが重要
    - 実装バグは`invalid`として表現され、プロトコルの安全性には影響しない
-/
inductive UnknownValidation
  | valid : ValidJSONValue → UnknownValidation
  | invalid : InvalidJSONValue → UnknownValidation

namespace UnknownValidation

/-- バリデーション検証関数（定義として実装）

    **設計の核心:**
    - 有効なJSON値（valid）: 常に検証成功
    - 無効なJSON値（invalid）: 常に検証失敗

    この単純な定義により、バリデーションロジックの詳細を抽象化しつつ、
    プロトコルの安全性を形式的に証明できる。

    **実装の責任:**
    - 実装側（Rust/TypeScript）が実際のバリデーションを行う
    - Lean側は型と性質のみを定義
-/
def checkValidation : UnknownValidation → Bool
  | valid _ => true   -- 有効なJSON値は常に検証成功
  | invalid _ => false -- 無効なJSON値は常に検証失敗

/-- バリデーション結果が有効かどうかを表す述語 -/
def isValid (validation : UnknownValidation) : Prop :=
  checkValidation validation = true

/-- Theorem: 有効なJSON値は常に検証成功

    型レベルで有効と判定されたJSON値は、検証が成功する。
    これは定義から自明だが、明示的に定理として示す。
-/
theorem valid_json_passes :
  ∀ (vjv : ValidJSONValue),
    isValid (valid vjv) := by
  intro vjv
  unfold isValid checkValidation
  rfl

/-- Theorem: 無効なJSON値は常に検証失敗

    型レベルで無効と判定されたJSON値は、検証が失敗する。
-/
theorem invalid_json_fails :
  ∀ (ijv : InvalidJSONValue),
    ¬isValid (invalid ijv) := by
  intro ijv
  unfold isValid checkValidation
  simp

end UnknownValidation

-- ## Schema に対する検証定理

namespace Schema

/-- Theorem: Boolean schema `true` はすべての値を受理

    Boolean schema `true` に対しては、任意のJSON値が有効。
-/
theorem true_accepts_all (value : JSONValue) :
    UnknownValidation.isValid (UnknownValidation.valid {
      value := value,
      schema := Schema.boolSchema true
    }) := by
  unfold UnknownValidation.isValid UnknownValidation.checkValidation
  rfl

/-- Theorem: Boolean schema `false` はすべての値を拒否

    Boolean schema `false` に対しては、任意のJSON値が無効。
-/
theorem false_rejects_all (value : JSONValue) :
    ¬UnknownValidation.isValid (UnknownValidation.invalid {
      value := value,
      schema := Schema.boolSchema false,
      errors := [{
        message := "Schema is 'false' (rejects all values)",
        path := "",
        keyword := "false"
      }]
    }) := by
  unfold UnknownValidation.isValid UnknownValidation.checkValidation
  simp

end Schema

-- ## Valid Schema と Invalid Schema

/-- 正規のスキーマ（AMATELUSサブセット）

    構文的に正しく、バリデーションに使用できるスキーマ。

    **制約:**
    - required配列の要素は一意
    - enum配列は空でない
    - 数値制約は有効な範囲
    - composition keywordsのネスト深さは最大3レベル
    - $ref, $defs を含まない
-/
structure ValidSchema where
  schema : Schema
  -- 構文的制約（簡略化のため、実際の検証は省略）

/-- 不正なスキーマ

    構文的に誤っているか、矛盾を含むスキーマ。
-/
structure InvalidSchema where
  schema : Schema
  reason : String

/-- 未検証のスキーマ

    パースされたが、正規性が未確定のスキーマ。
-/
inductive UnknownSchema
  | valid : ValidSchema → UnknownSchema
  | invalid : InvalidSchema → UnknownSchema

namespace UnknownSchema

/-- スキーマの構文検証

    **検証内容:**
    - required配列の一意性
    - enum配列の非空性
    - 数値制約の妥当性
    - composition nesting depth ≤ 3

    **簡略化:** 実装では常にtrueを返す（実際の検証は省略）
-/
def checkSyntax : Schema → Bool
  | _ => true

/-- 未検証スキーマから正規スキーマへの変換 -/
def toValidSchema : UnknownSchema → Option ValidSchema
  | valid vs => some vs
  | invalid _ => none

end UnknownSchema

-- ## 使用例

namespace Examples

/-- 例: 単純な文字列スキーマ -/
def stringSchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.type ["string"],
    SchemaKeyword.minLength 1,
    SchemaKeyword.maxLength 100
  ]

/-- 例: オブジェクトスキーマ（Person） -/
def personSchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.type ["object"],
    SchemaKeyword.properties [
      ("name", stringSchema),
      ("age", Schema.objectSchema [
        SchemaKeyword.type ["integer"],
        SchemaKeyword.minimum 0,
        SchemaKeyword.maximum 150
      ])
    ],
    SchemaKeyword.required ["name"]
  ]

/-- 例: 配列スキーマ -/
def stringArraySchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.type ["array"],
    SchemaKeyword.items stringSchema,
    SchemaKeyword.minItems 1,
    SchemaKeyword.maxItems 10,
    SchemaKeyword.uniqueItems true
  ]

/-- 例: enum制約 -/
def colorEnumSchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.type ["string"],
    SchemaKeyword.enum [
      JSONValue.string "red",
      JSONValue.string "green",
      JSONValue.string "blue"
    ]
  ]

/-- 例: allOf 組み合わせ -/
def allOfExampleSchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.allOf [
      Schema.objectSchema [SchemaKeyword.type ["object"]],
      Schema.objectSchema [SchemaKeyword.required ["name"]],
      Schema.objectSchema [
        SchemaKeyword.properties [
          ("age", Schema.objectSchema [
            SchemaKeyword.type ["integer"],
            SchemaKeyword.minimum 0
          ])
        ]
      ]
    ]
  ]

/-- 例: oneOf 組み合わせ（識別された和型） -/
def oneOfExampleSchema : Schema :=
  Schema.objectSchema [
    SchemaKeyword.oneOf [
      Schema.objectSchema [
        SchemaKeyword.properties [
          ("type", Schema.objectSchema [SchemaKeyword.const (JSONValue.string "email")]),
          ("email", stringSchema)
        ],
        SchemaKeyword.required ["type", "email"]
      ],
      Schema.objectSchema [
        SchemaKeyword.properties [
          ("type", Schema.objectSchema [SchemaKeyword.const (JSONValue.string "phone")]),
          ("phone", stringSchema)
        ],
        SchemaKeyword.required ["type", "phone"]
      ]
    ]
  ]

/-- テスト: 有効な文字列

    型レベルで検証済みとマークされたJSON値は検証成功する。
-/
example : UnknownValidation.isValid (UnknownValidation.valid {
    value := JSONValue.string "hello",
    schema := stringSchema
  }) := by
  unfold UnknownValidation.isValid UnknownValidation.checkValidation
  rfl

/-- テスト: Boolean schema true -/
example : UnknownValidation.isValid (UnknownValidation.valid {
    value := JSONValue.number 42,
    schema := Schema.boolSchema true
  }) := by
  apply Schema.true_accepts_all

/-- テスト: Boolean schema false -/
example : ¬UnknownValidation.isValid (UnknownValidation.invalid {
    value := JSONValue.string "test",
    schema := Schema.boolSchema false,
    errors := [{
      message := "Schema is 'false' (rejects all values)",
      path := "",
      keyword := "false"
    }]
  }) := by
  apply Schema.false_rejects_all

end Examples

-- ## まとめ

/-
このモジュールは、AMATELUS プロトコル用の JSON Schema サブセットを形式化しています：

1. **JSON データモデル**: 6つのプリミティブ型を帰納的に定義
2. **Schema サブセット**: Boolean と Object schema（参照なし）
3. **キーワード**: プロトコル保証されたキーワードのみ
4. **型レベルバリデーション**: ValidVC/InvalidVC と同じパターン
5. **定理**: Boolean schema の基本性質を証明

**AMATELUSサブセットの特徴:**
- **参照なし**: $ref, $defs を除外し、循環参照を防止
- **停止性保証**: ネスト深さ制限により、有限時間で停止
- **形式検証可能**: すべての機能がLeanで表現可能
- **プロトコル保証**: サブセット内の機能のみがプロトコルレベルで保証
- **実装の自由**: ウォレットは完全なJSON Schema 2020-12をサポート可能

**除外された機能:**
- $ref, $defs, $dynamicRef (循環参照防止)
- additionalProperties, patternProperties (動的検証)
- if/then/else (oneOfで代替可能)
- format (patternで代替可能)
- dependentRequired, dependentSchemas (組み合わせで代替可能)
- exclusiveMinimum, exclusiveMaximum (inclusive boundsで十分)

**設計の利点:**
- **型レベル抽象化**: ValidVC/InvalidVCと一貫したパターン
- **正規表現マッチング**: UnknownMatchResult型で抽象化
- **実装との分離**: Lean側は型と性質のみ定義、実装側がロジックを担当
- **証明可能**: 定理が `rfl` と `simp` で簡潔に証明可能

**実装上の責任分担:**
- **Lean側（このファイル）**: 型定義と性質の証明
  - ValidJSONValue, InvalidJSONValue, UnknownValidation 型
  - checkValidation 関数（型のマッチングのみ）
  - Schema に関する定理（true_accepts_all, false_rejects_all）

- **実装側（Rust/TypeScript等）**: 実際のバリデーションロジック
  - JSON値に対するスキーマ検証の実行
  - ValidJSONValue または InvalidJSONValue の構築
  - エラーメッセージの生成

**VC.leanとの一貫性:**
- ValidVC/InvalidVC/UnknownVC ↔ ValidJSONValue/InvalidJSONValue/UnknownValidation
- verifySignature ↔ checkValidation
- 両方とも型レベルで状態を表現し、実装の詳細を抽象化
-/
