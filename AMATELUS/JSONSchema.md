# JSON Schema Specification 2020-12

**Status**: JSON Schema Specification (Latest Stable Version)
**Source**: https://json-schema.org/specification.html
**Purpose**: Technical reference for formal specification in Lean

---

## 1. Abstract

JSON Schema is a vocabulary that allows you to annotate and validate JSON documents. It provides:
- **Declarative format**: Describe the structure and constraints of JSON data
- **Machine-readable**: Can be automatically processed by validation tools
- **Human-friendly**: Clear and intuitive syntax for defining data models
- **Extensible**: Support for custom vocabularies and keywords

JSON Schema is used for:
- Validating JSON data structure and content
- Documenting JSON APIs and data formats
- Generating test data and documentation
- Enabling code generation and IDE support

---

## 2. Specification Documents

The JSON Schema specification is composed of three main documents:

### 2.1 Core Specification

**JSON Schema Core** defines the basic foundation of JSON Schema:
- Schema structure and identification
- Core keywords ($id, $schema, $ref, etc.)
- Vocabulary system
- Reference resolution
- Extensibility mechanisms

**URL**: https://json-schema.org/draft/2020-12/json-schema-core

### 2.2 Validation Specification

**JSON Schema Validation** defines keywords for validation:
- Type system
- Validation keywords for different data types
- Format annotations
- Conditional validation
- Schema composition

**URL**: https://json-schema.org/draft/2020-12/json-schema-validation

### 2.3 Relative JSON Pointers

**Relative JSON Pointers** extends JSON Pointer syntax:
- Relative references within documents
- Upward navigation in data structures

**URL**: https://json-schema.org/draft/2020-12/relative-json-pointer

---

## 3. Core Concepts

### 3.1 Schema and Instance

**Instance**: A JSON document being validated (the data)

**Schema**: A JSON document that describes the rules and constraints for the instance

**Validation**: The process of checking whether an instance conforms to a schema

### 3.2 Schema Structure

A JSON Schema can be:
- **Boolean schema**:
  - `true`: Accepts any instance
  - `false`: Rejects all instances
- **Object schema**: Contains keywords that define validation rules

**Example**:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/person.schema.json",
  "title": "Person",
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "age": {
      "type": "integer",
      "minimum": 0
    }
  },
  "required": ["name"]
}
```

### 3.3 Keyword Categories

JSON Schema keywords are classified into five categories:

1. **Identifiers**: Define schema identity and location ($id, $schema)
2. **Assertions**: Impose constraints on the instance (type, minimum, pattern)
3. **Annotations**: Attach metadata to instances (title, description, default)
4. **Applicators**: Apply subschemas to instances (properties, items, allOf)
5. **Reserved**: Reserved for future use or special purposes

---

## 4. Core Keywords

### 4.1 `$schema` (OPTIONAL)

- **Type**: String (URI)
- **Purpose**: Declares which dialect of JSON Schema the schema follows
- **Usage**: Should be the meta-schema URI
- **Default**: If omitted, the latest dialect is assumed

**Example**:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema"
}
```

### 4.2 `$id` (OPTIONAL)

- **Type**: String (URI)
- **Purpose**: Declares a unique identifier for the schema
- **Usage**: Used for reference resolution and schema identification
- **Must**: Be an absolute URI (no fragment)

**Example**:
```json
{
  "$id": "https://example.com/schemas/person.json"
}
```

### 4.3 `$ref` (OPTIONAL)

- **Type**: String (URI-reference)
- **Purpose**: References another schema
- **Behavior**: The referenced schema is applied at the location of the $ref
- **Resolution**: Supports absolute, relative, and fragment references

**Examples**:

**Absolute reference**:
```json
{
  "$ref": "https://example.com/schemas/address.json"
}
```

**Relative reference**:
```json
{
  "$ref": "common/definitions.json#/definitions/timestamp"
}
```

**Internal reference**:
```json
{
  "$ref": "#/$defs/positiveInteger"
}
```

### 4.4 `$defs` (OPTIONAL)

- **Type**: Object
- **Purpose**: Contains reusable schema definitions
- **Note**: Replaces `definitions` from earlier drafts
- **Usage**: Store subschemas for reference

**Example**:
```json
{
  "$defs": {
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" }
      }
    }
  },
  "type": "object",
  "properties": {
    "billingAddress": { "$ref": "#/$defs/address" },
    "shippingAddress": { "$ref": "#/$defs/address" }
  }
}
```

### 4.5 `$dynamicRef` and `$dynamicAnchor` (OPTIONAL)

- **Type**: String (URI-reference)
- **Purpose**: Enable dynamic scope reference resolution
- **Use case**: Extending recursive schemas
- **Note**: Advanced feature for schema extensibility

**Example**:
```json
{
  "$id": "https://example.com/tree",
  "$dynamicAnchor": "node",
  "type": "object",
  "properties": {
    "data": true,
    "children": {
      "type": "array",
      "items": { "$dynamicRef": "#node" }
    }
  }
}
```

### 4.6 `$vocabulary` (OPTIONAL)

- **Type**: Object
- **Purpose**: Declares vocabularies used in a meta-schema
- **Keys**: Vocabulary URI
- **Values**: Boolean (true = required, false = optional)

**Example**:
```json
{
  "$vocabulary": {
    "https://json-schema.org/draft/2020-12/vocab/core": true,
    "https://json-schema.org/draft/2020-12/vocab/applicator": true,
    "https://json-schema.org/draft/2020-12/vocab/validation": true,
    "https://example.com/vocab/custom": false
  }
}
```

### 4.7 `$comment` (OPTIONAL)

- **Type**: String
- **Purpose**: Adds comments for schema authors
- **Note**: Has no effect on validation

**Example**:
```json
{
  "$comment": "This schema defines a user object",
  "type": "object"
}
```

---

## 5. Annotation Keywords

### 5.1 `title` (OPTIONAL)

- **Type**: String
- **Purpose**: Provides a short description of the schema
- **Usage**: Human-readable title for documentation

**Example**:
```json
{
  "title": "User Profile",
  "type": "object"
}
```

### 5.2 `description` (OPTIONAL)

- **Type**: String
- **Purpose**: Provides a detailed description of the schema
- **Usage**: Documentation and help text

**Example**:
```json
{
  "description": "A user profile containing personal information",
  "type": "object"
}
```

### 5.3 `default` (OPTIONAL)

- **Type**: Any
- **Purpose**: Supplies a default value for the instance
- **Note**: Does not affect validation; informational only

**Example**:
```json
{
  "type": "integer",
  "default": 0
}
```

### 5.4 `examples` (OPTIONAL)

- **Type**: Array
- **Purpose**: Provides example values
- **Usage**: Documentation and testing

**Example**:
```json
{
  "type": "string",
  "examples": ["user@example.com", "admin@example.org"]
}
```

### 5.5 `deprecated` (OPTIONAL)

- **Type**: Boolean
- **Purpose**: Marks a schema as deprecated
- **Usage**: Signal that usage is discouraged

**Example**:
```json
{
  "type": "string",
  "deprecated": true
}
```

### 5.6 `readOnly` and `writeOnly` (OPTIONAL)

- **Type**: Boolean
- **Purpose**: Indicate usage context
- **readOnly**: Property sent in responses but not in requests
- **writeOnly**: Property sent in requests but not in responses

**Example**:
```json
{
  "properties": {
    "id": {
      "type": "integer",
      "readOnly": true
    },
    "password": {
      "type": "string",
      "writeOnly": true
    }
  }
}
```

---

## 6. Type System

### 6.1 `type` (OPTIONAL)

- **Type**: String or Array of strings
- **Purpose**: Specifies the allowed JSON type(s)
- **Valid values**: "null", "boolean", "object", "array", "number", "string", "integer"

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

### 6.2 JSON Data Types

1. **null**: The null value
2. **boolean**: true or false
3. **object**: Unordered collection of key-value pairs
4. **array**: Ordered list of values
5. **number**: Numeric value (integer or floating-point)
6. **string**: Sequence of Unicode characters
7. **integer**: Number without fractional or exponent part

**Note**: "integer" is a subset of "number"

---

## 7. Validation Keywords by Type

### 7.1 String Validation

#### 7.1.1 `maxLength` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Maximum length of the string
- **Validation**: String length ≤ maxLength

**Example**:
```json
{
  "type": "string",
  "maxLength": 100
}
```

#### 7.1.2 `minLength` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Minimum length of the string
- **Validation**: String length ≥ minLength
- **Default**: 0

**Example**:
```json
{
  "type": "string",
  "minLength": 1
}
```

#### 7.1.3 `pattern` (OPTIONAL)

- **Type**: String (regular expression)
- **Purpose**: String must match the regular expression
- **Format**: ECMA-262 regular expression dialect

**Example**:
```json
{
  "type": "string",
  "pattern": "^[A-Za-z0-9]+$"
}
```

#### 7.1.4 `format` (OPTIONAL)

- **Type**: String
- **Purpose**: Semantic validation for strings
- **Common formats**:
  - `date-time`: RFC 3339 date-time
  - `date`: RFC 3339 full-date
  - `time`: RFC 3339 full-time
  - `email`: RFC 5321 email address
  - `hostname`: RFC 1123 hostname
  - `ipv4`: IPv4 address
  - `ipv6`: IPv6 address
  - `uri`: RFC 3986 URI
  - `uri-reference`: RFC 3986 URI reference
  - `uuid`: RFC 4122 UUID
  - `json-pointer`: RFC 6901 JSON Pointer

**Example**:
```json
{
  "type": "string",
  "format": "email"
}
```

### 7.2 Numeric Validation

#### 7.2.1 `maximum` (OPTIONAL)

- **Type**: Number
- **Purpose**: Maximum value (inclusive)
- **Validation**: value ≤ maximum

**Example**:
```json
{
  "type": "number",
  "maximum": 100
}
```

#### 7.2.2 `minimum` (OPTIONAL)

- **Type**: Number
- **Purpose**: Minimum value (inclusive)
- **Validation**: value ≥ minimum

**Example**:
```json
{
  "type": "number",
  "minimum": 0
}
```

#### 7.2.3 `exclusiveMaximum` (OPTIONAL)

- **Type**: Number
- **Purpose**: Maximum value (exclusive)
- **Validation**: value < exclusiveMaximum

**Example**:
```json
{
  "type": "number",
  "exclusiveMaximum": 100
}
```

#### 7.2.4 `exclusiveMinimum` (OPTIONAL)

- **Type**: Number
- **Purpose**: Minimum value (exclusive)
- **Validation**: value > exclusiveMinimum

**Example**:
```json
{
  "type": "number",
  "exclusiveMinimum": 0
}
```

#### 7.2.5 `multipleOf` (OPTIONAL)

- **Type**: Number (must be > 0)
- **Purpose**: Value must be a multiple of this number
- **Validation**: value = n × multipleOf (for some integer n)

**Example**:
```json
{
  "type": "number",
  "multipleOf": 0.01
}
```

### 7.3 Array Validation

#### 7.3.1 `maxItems` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Maximum number of items
- **Validation**: array.length ≤ maxItems

**Example**:
```json
{
  "type": "array",
  "maxItems": 10
}
```

#### 7.3.2 `minItems` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Minimum number of items
- **Validation**: array.length ≥ minItems
- **Default**: 0

**Example**:
```json
{
  "type": "array",
  "minItems": 1
}
```

#### 7.3.3 `uniqueItems` (OPTIONAL)

- **Type**: Boolean
- **Purpose**: All items must be unique
- **Validation**: No two items are equal
- **Default**: false

**Example**:
```json
{
  "type": "array",
  "uniqueItems": true
}
```

#### 7.3.4 `items` (OPTIONAL)

- **Type**: Schema or boolean
- **Purpose**: Schema for array items
- **Behavior**: Applied to all items in the array

**Example**:
```json
{
  "type": "array",
  "items": {
    "type": "string"
  }
}
```

#### 7.3.5 `prefixItems` (OPTIONAL)

- **Type**: Array of schemas
- **Purpose**: Schema for each position in array (tuple validation)
- **Behavior**: Applied to items by position

**Example**:
```json
{
  "type": "array",
  "prefixItems": [
    { "type": "string" },
    { "type": "number" },
    { "type": "boolean" }
  ]
}
```

#### 7.3.6 `contains` (OPTIONAL)

- **Type**: Schema
- **Purpose**: At least one item must match the schema
- **Validation**: Array must contain at least one matching item

**Example**:
```json
{
  "type": "array",
  "contains": {
    "type": "string",
    "pattern": "^admin"
  }
}
```

#### 7.3.7 `maxContains` and `minContains` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Control number of items matching `contains` schema
- **Validation**: Number of matching items within range

**Example**:
```json
{
  "type": "array",
  "contains": { "type": "number" },
  "minContains": 1,
  "maxContains": 3
}
```

### 7.4 Object Validation

#### 7.4.1 `maxProperties` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Maximum number of properties
- **Validation**: Object.keys(value).length ≤ maxProperties

**Example**:
```json
{
  "type": "object",
  "maxProperties": 10
}
```

#### 7.4.2 `minProperties` (OPTIONAL)

- **Type**: Non-negative integer
- **Purpose**: Minimum number of properties
- **Validation**: Object.keys(value).length ≥ minProperties
- **Default**: 0

**Example**:
```json
{
  "type": "object",
  "minProperties": 1
}
```

#### 7.4.3 `required` (OPTIONAL)

- **Type**: Array of strings (must be unique)
- **Purpose**: List of required property names
- **Validation**: All specified properties must exist

**Example**:
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

#### 7.4.4 `properties` (OPTIONAL)

- **Type**: Object (property names → schemas)
- **Purpose**: Define schemas for specific properties
- **Behavior**: Validates properties that are present

**Example**:
```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string"
    },
    "age": {
      "type": "integer",
      "minimum": 0
    }
  }
}
```

#### 7.4.5 `patternProperties` (OPTIONAL)

- **Type**: Object (regex patterns → schemas)
- **Purpose**: Define schemas for properties matching patterns
- **Behavior**: Applied to properties whose names match the regex

**Example**:
```json
{
  "type": "object",
  "patternProperties": {
    "^S_": { "type": "string" },
    "^I_": { "type": "integer" }
  }
}
```

#### 7.4.6 `additionalProperties` (OPTIONAL)

- **Type**: Schema or boolean
- **Purpose**: Schema for properties not covered by `properties` or `patternProperties`
- **Behavior**:
  - `false`: No additional properties allowed
  - `true` or schema: Additional properties must match schema

**Example**:
```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" }
  },
  "additionalProperties": false
}
```

#### 7.4.7 `propertyNames` (OPTIONAL)

- **Type**: Schema
- **Purpose**: Schema that all property names must match
- **Validation**: Each property name validated against schema

**Example**:
```json
{
  "type": "object",
  "propertyNames": {
    "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
  }
}
```

#### 7.4.8 `dependentRequired` (OPTIONAL)

- **Type**: Object (property name → array of property names)
- **Purpose**: If property exists, specified properties are required
- **Validation**: Conditional required properties

**Example**:
```json
{
  "type": "object",
  "properties": {
    "creditCard": { "type": "string" },
    "billingAddress": { "type": "string" }
  },
  "dependentRequired": {
    "creditCard": ["billingAddress"]
  }
}
```

#### 7.4.9 `dependentSchemas` (OPTIONAL)

- **Type**: Object (property name → schema)
- **Purpose**: If property exists, apply additional schema
- **Validation**: Conditional schema application

**Example**:
```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" }
  },
  "dependentSchemas": {
    "creditCard": {
      "properties": {
        "billingAddress": { "type": "string" }
      },
      "required": ["billingAddress"]
    }
  }
}
```

---

## 8. Generic Validation Keywords

### 8.1 `enum` (OPTIONAL)

- **Type**: Array (must be non-empty, should have unique items)
- **Purpose**: Value must be one of the enumerated values
- **Validation**: value ∈ enum

**Example**:
```json
{
  "type": "string",
  "enum": ["red", "green", "blue"]
}
```

### 8.2 `const` (OPTIONAL)

- **Type**: Any
- **Purpose**: Value must exactly equal this constant
- **Validation**: value === const

**Example**:
```json
{
  "type": "string",
  "const": "fixed-value"
}
```

---

## 9. Schema Composition

### 9.1 `allOf` (OPTIONAL)

- **Type**: Array of schemas (must be non-empty)
- **Purpose**: Instance must validate against ALL subschemas
- **Validation**: ∀ schema ∈ allOf: validate(instance, schema)

**Example**:
```json
{
  "allOf": [
    { "type": "object" },
    {
      "properties": {
        "name": { "type": "string" }
      },
      "required": ["name"]
    },
    {
      "properties": {
        "age": { "type": "integer" }
      }
    }
  ]
}
```

### 9.2 `anyOf` (OPTIONAL)

- **Type**: Array of schemas (must be non-empty)
- **Purpose**: Instance must validate against AT LEAST ONE subschema
- **Validation**: ∃ schema ∈ anyOf: validate(instance, schema)

**Example**:
```json
{
  "anyOf": [
    { "type": "string" },
    { "type": "number" }
  ]
}
```

### 9.3 `oneOf` (OPTIONAL)

- **Type**: Array of schemas (must be non-empty)
- **Purpose**: Instance must validate against EXACTLY ONE subschema
- **Validation**: |{schema ∈ oneOf: validate(instance, schema)}| = 1

**Example**:
```json
{
  "oneOf": [
    {
      "type": "object",
      "properties": {
        "type": { "const": "email" },
        "email": { "type": "string", "format": "email" }
      },
      "required": ["type", "email"]
    },
    {
      "type": "object",
      "properties": {
        "type": { "const": "phone" },
        "phone": { "type": "string" }
      },
      "required": ["type", "phone"]
    }
  ]
}
```

### 9.4 `not` (OPTIONAL)

- **Type**: Schema
- **Purpose**: Instance must NOT validate against the subschema
- **Validation**: ¬ validate(instance, schema)

**Example**:
```json
{
  "not": {
    "type": "null"
  }
}
```

---

## 10. Conditional Validation

### 10.1 `if`, `then`, `else` (OPTIONAL)

- **Type**: Schema
- **Purpose**: Conditional schema application
- **Behavior**:
  - If instance validates against `if`, apply `then` schema
  - If instance does not validate against `if`, apply `else` schema

**Example**:
```json
{
  "type": "object",
  "properties": {
    "country": { "type": "string" }
  },
  "if": {
    "properties": {
      "country": { "const": "USA" }
    }
  },
  "then": {
    "properties": {
      "zipCode": { "pattern": "^[0-9]{5}$" }
    },
    "required": ["zipCode"]
  },
  "else": {
    "properties": {
      "postalCode": { "type": "string" }
    }
  }
}
```

---

## 11. Validation Process

### 11.1 Validation Algorithm (High-Level)

```
function validate(instance, schema):
  1. If schema is boolean:
     - If true, return valid
     - If false, return invalid

  2. If schema is object:
     - For each keyword in schema:
       - Apply keyword validation to instance
       - If any validation fails, return invalid
     - Return valid

  3. Collect annotations during validation

  4. Return validation result with annotations
```

### 11.2 Keyword Evaluation Order

- Keywords are generally independent
- Some keywords depend on annotations from other keywords
- Evaluation order is typically:
  1. Applicators (apply subschemas)
  2. Assertions (check constraints)
  3. Annotations (collect metadata)

### 11.3 Validation Output

Validation produces:
- **Boolean result**: Valid or invalid
- **Annotations**: Metadata collected during validation
- **Errors**: Detailed error information (if invalid)

**Output formats**:
- **Flag**: Simple boolean
- **Basic**: Includes error messages
- **Detailed**: Includes all validation information
- **Verbose**: Includes every step of validation

---

## 12. Reference Resolution

### 12.1 URI Resolution

JSON Schema uses URIs for:
- Schema identification ($id)
- Schema references ($ref, $dynamicRef)
- Vocabulary identification ($vocabulary)

**Resolution rules**:
1. Absolute URI: Used as-is
2. Relative URI: Resolved against base URI
3. Fragment: Identifies location within schema

### 12.2 JSON Pointer

- **Format**: `#/path/to/location`
- **Purpose**: Navigate within JSON documents
- **Syntax**: Slash-separated path components
- **Escaping**: `~0` for `~`, `~1` for `/`

**Example**:
```json
{
  "$id": "https://example.com/schema.json",
  "$defs": {
    "address": {
      "type": "object"
    }
  }
}
```
Reference: `https://example.com/schema.json#/$defs/address`

### 12.3 Base URI

- Each schema has a base URI for resolution
- Base URI is determined by:
  1. $id keyword in current schema
  2. $id in parent schemas
  3. URI used to retrieve the schema

---

## 13. Conformance

### 13.1 Conformant Schema

A conformant JSON Schema:
- **MUST** be valid JSON
- **SHOULD** include $schema keyword
- **MUST** follow keyword syntax rules
- **MUST** have unique items in required array
- **MUST** have valid URI in $id (if present)
- **MUST** use defined keywords correctly

### 13.2 Conformant Validator

A conformant validator:
- **MUST** implement core vocabulary
- **MUST** recognize $schema keyword
- **MUST** handle boolean schemas (true/false)
- **MUST** implement required vocabularies
- **SHOULD** support format validation
- **MAY** support additional vocabularies
- **MUST** report unrecognized vocabularies (if required)

### 13.3 Vocabulary Support

**Core vocabulary** (REQUIRED):
- Schema identification and structure
- Reference resolution

**Applicator vocabulary** (commonly used):
- properties, items, allOf, anyOf, oneOf, not

**Validation vocabulary** (commonly used):
- type, enum, const
- String, number, array, object validators

**Format annotation vocabulary** (OPTIONAL):
- format keyword

---

## 14. Security Considerations

### 14.1 Schema Validation

- **Schema complexity**: Complex schemas may cause performance issues
- **Regular expressions**: Unsafe patterns may cause ReDoS attacks
- **Mitigation**: Implement timeouts, complexity limits

### 14.2 Reference Resolution

- **Remote references**: May cause network requests
- **Circular references**: May cause infinite loops
- **Mitigation**: Cache schemas, detect cycles, limit depth

### 14.3 Format Validation

- **Email, hostname**: May leak information
- **URI validation**: May cause SSRF attacks
- **Mitigation**: Be cautious with network-based formats

### 14.4 User-Supplied Schemas

- **Untrusted schemas**: May be malicious
- **Code injection**: Format validators may execute code
- **Mitigation**: Sandbox execution, validate schemas, restrict formats

---

## 15. MUST/SHOULD/MAY Summary

### 15.1 MUST Requirements (Normative)

1. Schema **MUST** be valid JSON
2. Boolean schema `true` **MUST** accept all instances
3. Boolean schema `false` **MUST** reject all instances
4. `$id` **MUST** be an absolute URI (no fragment)
5. `required` array **MUST** contain unique strings
6. `enum` array **MUST** be non-empty
7. Numeric constraints (minimum, maximum) **MUST** be numbers
8. String length constraints **MUST** be non-negative integers
9. Array/object size constraints **MUST** be non-negative integers
10. `multipleOf` **MUST** be greater than 0
11. Validator **MUST** implement core vocabulary
12. Validator **MUST** handle boolean schemas
13. Validator **MUST** report validation results accurately
14. Regular expressions **MUST** follow ECMA-262 dialect
15. JSON Pointers **MUST** follow RFC 6901

### 15.2 SHOULD Requirements (Recommended)

1. Schema **SHOULD** include `$schema` keyword
2. Validator **SHOULD** support format validation
3. `enum` array **SHOULD** contain unique values
4. Validator **SHOULD** implement validation vocabulary
5. Validator **SHOULD** implement applicator vocabulary
6. Schemas **SHOULD** include documentation (title, description)
7. Complex schemas **SHOULD** use $defs for reusability
8. Validators **SHOULD** provide detailed error messages
9. Validators **SHOULD** implement security limits
10. External references **SHOULD** be cached

### 15.3 MAY Requirements (Optional)

1. Schema **MAY** include annotation keywords
2. Schema **MAY** use $defs for definitions
3. Schema **MAY** include $comment for documentation
4. Validator **MAY** support custom vocabularies
5. Validator **MAY** provide verbose output
6. Validator **MAY** implement format assertion
7. Schema **MAY** use conditional validation (if/then/else)
8. Schema **MAY** use schema composition (allOf/anyOf/oneOf)
9. Validator **MAY** optimize validation
10. Validator **MAY** support extensions

---

## 16. Key Concepts for Formalization

### 16.1 Type System

```
JSONValue = Null | Boolean | Number | String | Array | Object
Schema = Boolean | SchemaObject
SchemaObject = Map<Keyword, Value>
Keyword = String
ValidationResult = Valid | Invalid(errors)
```

### 16.2 Validation Predicates

```
validate(instance: JSONValue, schema: Schema) -> ValidationResult

isValid(instance, schema) -> Boolean
  = match schema:
      true -> true
      false -> false
      object -> allKeywordsValid(instance, schema)

allKeywordsValid(instance, schema) -> Boolean
  = ∀ (keyword, value) ∈ schema:
      validateKeyword(instance, keyword, value)
```

### 16.3 Type Validation

```
validateType(instance, type) -> Boolean
  = match type:
      "null" -> instance === null
      "boolean" -> instance is boolean
      "number" -> instance is number
      "integer" -> instance is number ∧ isInteger(instance)
      "string" -> instance is string
      "array" -> instance is array
      "object" -> instance is object
      [t1, t2, ...] -> validateType(instance, t1) ∨ validateType(instance, t2) ∨ ...
```

### 16.4 Core Invariants

1. **Boolean schemas**: `true` accepts all, `false` rejects all
2. **Type consistency**: Instance must match declared type
3. **Composition consistency**: allOf/anyOf/oneOf follow logical rules
4. **Reference transitivity**: $ref preserves validation semantics
5. **Annotation accumulation**: Annotations collected during traversal

---

## 17. Notes for Lean Formalization

### 17.1 Challenges

1. **JSON representation**: Need inductive type for JSON values
2. **Schema extensibility**: Open-ended keyword system
3. **Reference resolution**: URI and JSON Pointer navigation
4. **Regular expressions**: Pattern matching requires external validation
5. **Format validation**: Depends on external specifications

### 17.2 Recommended Approach

1. **JSON Model**: Define inductive type for JSON values
2. **Schema Model**: Define schema as keyword map with well-formed conditions
3. **Core Keywords**: Implement as functions (instance → schema → Boolean)
4. **Validation**: Define as recursive function over schema structure
5. **References**: Abstract as resolution function (URI → Schema)
6. **Formats**: Axiomatize or stub out format validators
7. **Invariants**: Prove properties of validation algorithm

### 17.3 Abstraction Layers

```
Layer 1: JSON Data Model (values, types)
Layer 2: Schema Structure (keywords, boolean schemas)
Layer 3: Keyword Semantics (validation rules)
Layer 4: Schema Composition (allOf, anyOf, oneOf, not)
Layer 5: Reference Resolution (URIs, pointers)
Layer 6: Validation Algorithm (recursive validation)
Layer 7: Properties (soundness, completeness, termination)
```

### 17.4 Formalization Strategy

1. **Start with JSON**: Define JSON value type and operations
2. **Define Schema Type**: Model schema as ADT or record
3. **Implement Keywords**: Define validation for each keyword
4. **Composition**: Implement allOf/anyOf/oneOf/not
5. **Reference**: Abstract reference resolution
6. **Validation Function**: Recursive validator over schema
7. **Prove Properties**: Termination, determinism, correctness

### 17.5 Proof Goals

1. **Termination**: Validation always terminates (handle cycles)
2. **Determinism**: Same input produces same result
3. **Compositionality**: Validation composes correctly
4. **Reference soundness**: $ref preserves validation
5. **Type soundness**: If validates, instance has declared type

---

## 18. Examples

### 18.1 Simple Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/person.schema.json",
  "title": "Person",
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string",
      "description": "The person's first name"
    },
    "lastName": {
      "type": "string",
      "description": "The person's last name"
    },
    "age": {
      "type": "integer",
      "description": "Age in years",
      "minimum": 0
    }
  },
  "required": ["firstName", "lastName"]
}
```

### 18.2 Schema with Array

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/arrays.schema.json",
  "title": "Product List",
  "type": "object",
  "properties": {
    "products": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {
            "type": "integer"
          },
          "name": {
            "type": "string"
          },
          "price": {
            "type": "number",
            "minimum": 0
          }
        },
        "required": ["id", "name", "price"]
      },
      "minItems": 1
    }
  }
}
```

### 18.3 Schema with References

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/user.schema.json",
  "title": "User",
  "type": "object",
  "$defs": {
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" },
        "state": { "type": "string" },
        "zipCode": { "type": "string", "pattern": "^[0-9]{5}$" }
      },
      "required": ["street", "city", "state", "zipCode"]
    }
  },
  "properties": {
    "name": { "type": "string" },
    "billingAddress": { "$ref": "#/$defs/address" },
    "shippingAddress": { "$ref": "#/$defs/address" }
  },
  "required": ["name", "billingAddress"]
}
```

### 18.4 Schema with Composition

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/composition.schema.json",
  "title": "Employee or Contractor",
  "oneOf": [
    {
      "type": "object",
      "properties": {
        "type": { "const": "employee" },
        "employeeId": { "type": "integer" },
        "department": { "type": "string" }
      },
      "required": ["type", "employeeId", "department"]
    },
    {
      "type": "object",
      "properties": {
        "type": { "const": "contractor" },
        "company": { "type": "string" },
        "endDate": { "type": "string", "format": "date" }
      },
      "required": ["type", "company", "endDate"]
    }
  ]
}
```

### 18.5 Conditional Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/conditional.schema.json",
  "title": "Account",
  "type": "object",
  "properties": {
    "accountType": {
      "type": "string",
      "enum": ["personal", "business"]
    },
    "name": { "type": "string" }
  },
  "required": ["accountType", "name"],
  "if": {
    "properties": {
      "accountType": { "const": "business" }
    }
  },
  "then": {
    "properties": {
      "taxId": { "type": "string" },
      "companyName": { "type": "string" }
    },
    "required": ["taxId", "companyName"]
  }
}
```

---

## 19. References

### 19.1 Specifications

- JSON Schema 2020-12: https://json-schema.org/draft/2020-12/json-schema-core
- JSON Schema Validation: https://json-schema.org/draft/2020-12/json-schema-validation
- Relative JSON Pointers: https://json-schema.org/draft/2020-12/relative-json-pointer
- JSON Schema Website: https://json-schema.org/

### 19.2 Related Standards

- JSON (RFC 8259): https://tools.ietf.org/html/rfc8259
- JSON Pointer (RFC 6901): https://tools.ietf.org/html/rfc6901
- URI (RFC 3986): https://tools.ietf.org/html/rfc3986
- Regular Expressions (ECMA-262): https://www.ecma-international.org/ecma-262/

### 19.3 Implementations

- Official implementations list: https://json-schema.org/implementations.html
- Test suite: https://github.com/json-schema-org/JSON-Schema-Test-Suite

---

## 20. Version History

- **Draft 2020-12**: Current stable version
- **Draft 2019-09**: Previous version
- **Draft-07**: Widely adopted version
- **Draft-06, Draft-05, Draft-04**: Earlier versions
- **Draft-03, Draft-02, Draft-01**: Initial drafts

**Migration guides**: https://json-schema.org/draft/2020-12/release-notes
