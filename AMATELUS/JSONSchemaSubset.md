# AMATELUS JSON Schema Subset Specification

**Status**: AMATELUS Protocol Specification (Draft)
**Version**: 1.0.0
**Base Specification**: JSON Schema 2020-12
**Purpose**: Formally verifiable subset for Verifiable Credentials

---

## 1. Abstract

This document defines a **formally verifiable subset** of JSON Schema 2020-12 for use in the AMATELUS protocol. The subset is designed to:

1. **Enable formal verification** in Lean 4 without axioms or partial definitions
2. **Guarantee termination** by eliminating circular references
3. **Ensure protocol-level interoperability** across all AMATELUS implementations
4. **Allow extended validation** by individual wallet implementations

### 1.1 Design Principles

- **Protocol Guarantee**: Only features in this subset are guaranteed by the AMATELUS protocol
- **Implementation Freedom**: Wallets MAY support full JSON Schema 2020-12
- **Formal Verification**: All features MUST be provably terminating in Lean 4
- **Deterministic Validation**: Same schema produces same result across all implementations

---

## 2. Excluded Features

The following JSON Schema features are **EXCLUDED** from AMATELUS protocol guarantees:

### 2.1 Reference Keywords (Prevents Circular References)

- `$ref` - Schema references (main source of non-termination)
- `$defs` - Schema definitions (only useful with `$ref`)
- `$dynamicRef` - Dynamic references
- `$dynamicAnchor` - Dynamic anchors

**Rationale**: These keywords enable circular references, making termination proof impossible.

**Example of excluded pattern**:
```json
{
  "$defs": {
    "node": {
      "properties": {
        "next": { "$ref": "#/$defs/node" }  // ❌ Circular reference
      }
    }
  }
}
```

### 2.2 Dynamic Property Validation

- `additionalProperties` - MAY exist but MUST be ignored by protocol
- `patternProperties` - Not supported
- `propertyNames` - Not supported
- `unevaluatedProperties` - Not supported
- `unevaluatedItems` - Not supported

**Rationale**: Dynamic property validation requires runtime iteration over unbounded sets.

**Protocol behavior**: If `additionalProperties` is present, it is **ignored** at protocol level. Wallets MAY choose to validate it.

### 2.3 Conditional Validation

- `if`, `then`, `else` - Conditional schemas

**Rationale**: Adds complexity without clear protocol-level benefit. Use `oneOf` instead.

### 2.4 Advanced Array Features

- `prefixItems` - Tuple validation (complex)
- `contains` - Existential validation (complex)
- `maxContains`, `minContains` - Count constraints

**Rationale**: `items` provides sufficient array validation for most use cases.

### 2.5 Format Annotations

- `format` - Semantic string formats (email, uri, date-time, etc.)

**Rationale**: Depends on external specifications. Use `pattern` for regex-based validation.

### 2.6 Dependency Keywords

- `dependentRequired` - Conditional required properties
- `dependentSchemas` - Conditional schema application

**Rationale**: Can be expressed using `oneOf` or `allOf`.

### 2.7 Exclusive Bounds

- `exclusiveMaximum` - Exclusive upper bound
- `exclusiveMinimum` - Exclusive lower bound

**Rationale**: `maximum` and `minimum` (inclusive) are sufficient for most cases.

### 2.8 Meta Keywords (Optional for Protocol)

- `$schema` - MAY be present but not validated
- `$id` - MAY be present but not used for resolution
- `$vocabulary` - Not supported
- `$comment` - Ignored

---

## 3. Supported Features

The following JSON Schema features are **SUPPORTED** and **GUARANTEED** by the AMATELUS protocol:

### 3.1 Schema Structure

#### 3.1.1 Boolean Schemas

✅ **Supported**

- `true` - Accepts all instances
- `false` - Rejects all instances

```json
true  // Accepts any value
```

```json
false  // Rejects any value
```

#### 3.1.2 Object Schemas

✅ **Supported**

Object schemas containing keyword-value pairs.

---

### 3.2 Type System

#### 3.2.1 `type` ✅

- **Type**: String or Array of strings
- **Purpose**: Specifies allowed JSON type(s)
- **Values**: `"null"`, `"boolean"`, `"object"`, `"array"`, `"number"`, `"string"`, `"integer"`

**Single type**:
```json
{
  "type": "string"
}
```

**Multiple types**:
```json
{
  "type": ["string", "number"]
}
```

---

### 3.3 String Validation

#### 3.3.1 `maxLength` ✅

- **Type**: Non-negative integer
- **Validation**: String length ≤ maxLength

```json
{
  "type": "string",
  "maxLength": 100
}
```

#### 3.3.2 `minLength` ✅

- **Type**: Non-negative integer
- **Validation**: String length ≥ minLength

```json
{
  "type": "string",
  "minLength": 1
}
```

#### 3.3.3 `pattern` ✅

- **Type**: String (ECMA-262 regular expression)
- **Validation**: String must match regex
- **Note**: Regex matching is **abstracted** in Lean formalization using `MatchedString`/`UnmatchedString` types

```json
{
  "type": "string",
  "pattern": "^[A-Za-z0-9]+$"
}
```

---

### 3.4 Numeric Validation

#### 3.4.1 `maximum` ✅

- **Type**: Number
- **Validation**: value ≤ maximum (inclusive)

```json
{
  "type": "number",
  "maximum": 100
}
```

#### 3.4.2 `minimum` ✅

- **Type**: Number
- **Validation**: value ≥ minimum (inclusive)

```json
{
  "type": "number",
  "minimum": 0
}
```

#### 3.4.3 `multipleOf` ✅

- **Type**: Number (must be > 0)
- **Validation**: value = n × multipleOf (for some integer n)

```json
{
  "type": "number",
  "multipleOf": 0.01
}
```

---

### 3.5 Array Validation

#### 3.5.1 `maxItems` ✅

- **Type**: Non-negative integer
- **Validation**: array.length ≤ maxItems

```json
{
  "type": "array",
  "maxItems": 10
}
```

#### 3.5.2 `minItems` ✅

- **Type**: Non-negative integer
- **Validation**: array.length ≥ minItems

```json
{
  "type": "array",
  "minItems": 1
}
```

#### 3.5.3 `uniqueItems` ✅

- **Type**: Boolean
- **Validation**: No duplicate items
- **Default**: false

```json
{
  "type": "array",
  "uniqueItems": true
}
```

#### 3.5.4 `items` ✅

- **Type**: Schema or boolean
- **Validation**: Applied to all array items

```json
{
  "type": "array",
  "items": {
    "type": "string",
    "minLength": 1
  }
}
```

---

### 3.6 Object Validation

#### 3.6.1 `maxProperties` ✅

- **Type**: Non-negative integer
- **Validation**: Number of properties ≤ maxProperties

```json
{
  "type": "object",
  "maxProperties": 10
}
```

#### 3.6.2 `minProperties` ✅

- **Type**: Non-negative integer
- **Validation**: Number of properties ≥ minProperties

```json
{
  "type": "object",
  "minProperties": 1
}
```

#### 3.6.3 `required` ✅

- **Type**: Array of unique strings
- **Validation**: All listed properties must exist

```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "email": { "type": "string" }
  },
  "required": ["name"]
}
```

#### 3.6.4 `properties` ✅

- **Type**: Object (property name → schema)
- **Validation**: Validates specified properties if present

```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "age": { "type": "integer", "minimum": 0 }
  }
}
```

#### 3.6.5 `additionalProperties` ⚠️ **Ignored**

- **Protocol behavior**: Keyword is **ignored** at protocol level
- **Wallet behavior**: Wallets MAY validate this keyword
- **Rationale**: Prevents dynamic property iteration

```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" }
  },
  "additionalProperties": false  // ⚠️ Ignored by protocol
}
```

---

### 3.7 Generic Validation

#### 3.7.1 `enum` ✅

- **Type**: Non-empty array
- **Validation**: value ∈ enum
- **Note**: Items SHOULD be unique

```json
{
  "type": "string",
  "enum": ["red", "green", "blue"]
}
```

#### 3.7.2 `const` ✅

- **Type**: Any JSON value
- **Validation**: value === const

```json
{
  "type": "string",
  "const": "fixed-value"
}
```

---

### 3.8 Schema Composition

**Nesting Limit**: Composition keywords (`allOf`, `anyOf`, `oneOf`, `not`) MUST NOT nest more than **3 levels deep**.

#### 3.8.1 `allOf` ✅ (Depth-Limited)

- **Type**: Non-empty array of schemas
- **Validation**: Instance must validate against ALL subschemas
- **Limit**: Max 3 levels of nesting

```json
{
  "allOf": [
    { "type": "object" },
    {
      "properties": {
        "name": { "type": "string" }
      },
      "required": ["name"]
    }
  ]
}
```

#### 3.8.2 `anyOf` ✅ (Depth-Limited)

- **Type**: Non-empty array of schemas
- **Validation**: Instance must validate against AT LEAST ONE subschema
- **Limit**: Max 3 levels of nesting

```json
{
  "anyOf": [
    { "type": "string" },
    { "type": "number" }
  ]
}
```

#### 3.8.3 `oneOf` ✅ (Depth-Limited)

- **Type**: Non-empty array of schemas
- **Validation**: Instance must validate against EXACTLY ONE subschema
- **Limit**: Max 3 levels of nesting

```json
{
  "oneOf": [
    {
      "properties": {
        "type": { "const": "email" },
        "email": { "type": "string" }
      },
      "required": ["type", "email"]
    },
    {
      "properties": {
        "type": { "const": "phone" },
        "phone": { "type": "string" }
      },
      "required": ["type", "phone"]
    }
  ]
}
```

#### 3.8.4 `not` ✅ (Depth-Limited)

- **Type**: Schema
- **Validation**: Instance must NOT validate against subschema
- **Limit**: Max 3 levels of nesting

```json
{
  "not": {
    "type": "null"
  }
}
```

**Nesting Example** (Max 3 levels):
```json
{
  "allOf": [                    // Level 1
    {
      "anyOf": [                // Level 2
        {
          "oneOf": [            // Level 3 ✅ OK
            { "type": "string" },
            { "type": "number" }
          ]
        }
      ]
    }
  ]
}
```

```json
{
  "allOf": [                    // Level 1
    {
      "anyOf": [                // Level 2
        {
          "oneOf": [            // Level 3
            {
              "allOf": [...]    // Level 4 ❌ Exceeds limit
            }
          ]
        }
      ]
    }
  ]
}
```

---

### 3.9 Annotation Keywords

#### 3.9.1 `title` ✅ (Informational)

- **Type**: String
- **Purpose**: Human-readable title
- **Validation**: No effect on validation

```json
{
  "title": "User Profile",
  "type": "object"
}
```

#### 3.9.2 `description` ✅ (Informational)

- **Type**: String
- **Purpose**: Detailed description
- **Validation**: No effect on validation

```json
{
  "description": "A user profile object",
  "type": "object"
}
```

#### 3.9.3 Other Annotations ⚠️ **Ignored**

- `default`, `examples`, `deprecated`, `readOnly`, `writeOnly`
- **Protocol behavior**: Ignored at protocol level
- **Wallet behavior**: Wallets MAY use these for UI/UX

---

## 4. Conformance

### 4.1 Conformant Schema

A schema is **AMATELUS-conformant** if:

1. It contains ONLY keywords from the [Supported Features](#3-supported-features) section
2. Composition nesting does NOT exceed 3 levels
3. `required` array contains unique strings
4. `enum` array is non-empty
5. Numeric constraints are valid numbers
6. String/array/object size constraints are non-negative integers
7. `multipleOf` is greater than 0

### 4.2 Conformant Validator

An **AMATELUS-conformant validator** MUST:

1. Validate all supported keywords correctly
2. **Ignore** excluded keywords without error
3. Enforce nesting depth limit (3 levels)
4. Produce deterministic results
5. Reject schemas exceeding nesting limits

### 4.3 Validation Behavior

**Protocol-level validation**:
- Only validates keywords in [Supported Features](#3-supported-features)
- Ignores `additionalProperties` and other excluded keywords
- Enforces structural limits (nesting depth)

**Wallet-level validation** (optional):
- MAY support full JSON Schema 2020-12
- MAY validate `additionalProperties`, `format`, etc.
- MUST still be compatible with protocol-level validation

---

## 5. Formal Verification in Lean

### 5.1 Termination Guarantee

All supported features are **provably terminating**:

1. **No circular references**: `$ref` excluded
2. **Bounded recursion**: Nesting depth limited to 3
3. **Finite structure**: All schemas have finite size

### 5.2 Lean Formalization

The subset is implemented in `AMATELUS/JSONSchema.lean`:

```lean
-- Supported keywords only
inductive SchemaKeyword
  | type : List String → SchemaKeyword
  | maxLength : Nat → SchemaKeyword
  | minLength : Nat → SchemaKeyword
  | pattern : String → SchemaKeyword
  | maximum : Float → SchemaKeyword
  | minimum : Float → SchemaKeyword
  | multipleOf : Float → SchemaKeyword
  | maxItems : Nat → SchemaKeyword
  | minItems : Nat → SchemaKeyword
  | uniqueItems : Bool → SchemaKeyword
  | items : Schema → SchemaKeyword
  | maxProperties : Nat → SchemaKeyword
  | minProperties : Nat → SchemaKeyword
  | required : List String → SchemaKeyword
  | properties : List (String × Schema) → SchemaKeyword
  | enum : List JSONValue → SchemaKeyword
  | const : JSONValue → SchemaKeyword
  | allOf : List Schema → SchemaKeyword
  | anyOf : List Schema → SchemaKeyword
  | oneOf : List Schema → SchemaKeyword
  | not : Schema → SchemaKeyword
  | title : String → SchemaKeyword
  | description : String → SchemaKeyword
  -- additionalProperties NOT included in validation
```

### 5.3 Validation Function

```lean
def validateKeyword (value : JSONValue) (keyword : SchemaKeyword)
    (validateSchema : JSONValue → Schema → ValidationResult)
    : ValidationResult :=
  match keyword with
  | SchemaKeyword.type types => ...
  | SchemaKeyword.allOf schemas =>
      let results := schemas.map (fun s => validateSchema value s)
      ValidationResult.combineAll results
  | ...
```

**Key property**: `validateSchema` is passed as parameter, enabling termination proof through structural recursion.

---

## 6. Examples

### 6.1 Simple Person Schema

```json
{
  "title": "Person",
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "age": {
      "type": "integer",
      "minimum": 0,
      "maximum": 150
    },
    "email": {
      "type": "string",
      "pattern": "^[^@]+@[^@]+\\.[^@]+$"
    }
  },
  "required": ["name"]
}
```

### 6.2 Array Schema

```json
{
  "title": "Tag List",
  "type": "array",
  "items": {
    "type": "string",
    "minLength": 1
  },
  "minItems": 1,
  "maxItems": 10,
  "uniqueItems": true
}
```

### 6.3 Union Type with `oneOf`

```json
{
  "title": "Contact Method",
  "oneOf": [
    {
      "type": "object",
      "properties": {
        "type": { "const": "email" },
        "address": { "type": "string" }
      },
      "required": ["type", "address"]
    },
    {
      "type": "object",
      "properties": {
        "type": { "const": "phone" },
        "number": { "type": "string" }
      },
      "required": ["type", "number"]
    }
  ]
}
```

### 6.4 Composition with `allOf`

```json
{
  "title": "Named Entity",
  "allOf": [
    {
      "type": "object",
      "properties": {
        "id": { "type": "string" }
      },
      "required": ["id"]
    },
    {
      "type": "object",
      "properties": {
        "name": { "type": "string" }
      },
      "required": ["name"]
    }
  ]
}
```

---

## 7. Migration Guide

### 7.1 From Full JSON Schema

If migrating from full JSON Schema 2020-12:

**Replace `$ref` with inline schemas**:
```json
// ❌ Before (uses $ref)
{
  "$defs": {
    "address": { "type": "object", ... }
  },
  "properties": {
    "billing": { "$ref": "#/$defs/address" }
  }
}

// ✅ After (inline)
{
  "properties": {
    "billing": { "type": "object", ... }
  }
}
```

**Replace `if/then/else` with `oneOf`**:
```json
// ❌ Before (uses if/then/else)
{
  "if": { "properties": { "country": { "const": "USA" } } },
  "then": { "properties": { "zipCode": ... } }
}

// ✅ After (uses oneOf)
{
  "oneOf": [
    {
      "allOf": [
        { "properties": { "country": { "const": "USA" } } },
        { "properties": { "zipCode": ... } }
      ]
    },
    { "properties": { "country": { "not": { "const": "USA" } } } }
  ]
}
```

**Remove `additionalProperties`**:
```json
// ⚠️ This keyword is ignored at protocol level
{
  "properties": { "name": { "type": "string" } },
  "additionalProperties": false  // Wallets MAY enforce, protocol ignores
}
```

### 7.2 Checking Nesting Depth

Ensure composition keywords don't exceed 3 levels:

```bash
# Use a linter or validator to check depth
amatelus-schema-lint --max-depth 3 schema.json
```

---

## 8. Security Considerations

### 8.1 Schema Complexity

- **Max depth**: 3 levels prevents deeply nested schemas
- **No recursion**: Eliminates infinite loops
- **Bounded size**: All schemas have finite representation

### 8.2 Regular Expressions

- **Pattern matching**: Abstracted in formal verification
- **ReDoS prevention**: Implementations SHOULD use timeout limits
- **Validation**: Wallets MUST validate regex syntax

### 8.3 Validation Performance

- **Deterministic**: Same input always produces same output
- **Bounded time**: No circular references, limited depth
- **Predictable**: Formal verification guarantees termination

---

## 9. Appendix

### 9.1 Quick Reference

| Feature | Status | Notes |
|---------|--------|-------|
| Boolean schemas (`true`/`false`) | ✅ Supported | |
| `type` | ✅ Supported | |
| `minLength`, `maxLength` | ✅ Supported | |
| `pattern` | ✅ Supported | Abstracted in Lean |
| `minimum`, `maximum` | ✅ Supported | Inclusive only |
| `multipleOf` | ✅ Supported | |
| `minItems`, `maxItems` | ✅ Supported | |
| `uniqueItems` | ✅ Supported | |
| `items` | ✅ Supported | Single schema only |
| `minProperties`, `maxProperties` | ✅ Supported | |
| `required` | ✅ Supported | |
| `properties` | ✅ Supported | |
| `enum`, `const` | ✅ Supported | |
| `allOf`, `anyOf`, `oneOf`, `not` | ✅ Supported | Max 3 level nesting |
| `title`, `description` | ✅ Supported | Informational only |
| `$ref`, `$defs` | ❌ Excluded | Prevents circular refs |
| `additionalProperties` | ⚠️ Ignored | Wallets MAY validate |
| `patternProperties` | ❌ Excluded | |
| `if`, `then`, `else` | ❌ Excluded | Use `oneOf` instead |
| `format` | ❌ Excluded | Use `pattern` instead |
| `prefixItems`, `contains` | ❌ Excluded | |
| `dependentRequired`, `dependentSchemas` | ❌ Excluded | |
| `exclusiveMinimum`, `exclusiveMaximum` | ❌ Excluded | |

### 9.2 Validation Result

Protocol-level validation produces:
- **Boolean**: `valid` or `invalid`
- **Errors**: List of validation errors (if invalid)
- **No annotations**: Annotations are informational only

---

## 10. References

- **Base Specification**: [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)
- **AMATELUS Protocol**: [Protocol Specification](../README.md)
- **Lean Formalization**: [AMATELUS/JSONSchema.lean](./JSONSchema.lean)
- **Full Specification**: [AMATELUS/JSONSchema.md](./JSONSchema.md)
