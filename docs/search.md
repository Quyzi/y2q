# Label Search

`y2q` can find objects by the labels attached to them, using a small boolean
query language. A query combines one or more **conditions** (each tests a single
label) with the operators `and`, `or`, and `not`. Searching runs **server-side**
against the metadata index, so the daemon evaluates the query and returns only
matching objects.

- HTTP: `GET /api/v1/search` (see [api.md](api.md#get-apiv1search))
- CLI: `y2q search <alias>[/<bucket>[/<prefix>]] --query '<EXPR>'`

> Labels are the arbitrary `key=value` metadata you attach to objects at upload
> time (`y2q cp ... --label k=v`) or later (`y2q tag set ...`). Search never
> inspects object *contents* - only labels and the key/prefix.

---

## Table of contents

- [Quick start](#quick-start)
- [Conditions](#conditions)
  - [Operators](#operators)
  - [Label names](#label-names)
  - [Values: bare vs quoted](#values-bare-vs-quoted)
  - [Missing-label semantics](#missing-label-semantics)
- [Combining conditions](#combining-conditions)
  - [Operators and precedence](#operators-and-precedence)
  - [Parentheses](#parentheses)
  - [`not`](#not)
- [Regular expressions](#regular-expressions)
- [Whitespace and tokenization rules](#whitespace-and-tokenization-rules)
- [Search scope and parameters](#search-scope-and-parameters)
- [Pagination](#pagination)
- [Errors](#errors)
- [Worked examples](#worked-examples)
- [Performance and limits](#performance-and-limits)
- [Formal grammar](#formal-grammar)

---

## Quick start

```sh
# Objects in bucket `photos` labeled env=prod
y2q search prod/photos --query 'env == prod'

# Across every bucket on the server (note the trailing slash, no bucket)
y2q search prod/ --query 'env == prod and tier != test'

# Combine prefix narrowing (key starts with "2024/") with a label filter
y2q search prod/photos/2024/ --query 'owner == alice'

# JSON output for scripting
y2q --json search prod/photos --query 'team =~ "infra|sre"'
```

The HTTP equivalent of the first example:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  --get "https://y2qd.example/api/v1/search" \
  --data-urlencode 'q=env == prod' \
  --data-urlencode 'bucket=photos'
```

---

## Conditions

A condition is the atom of a query. It has the form:

```
<name> <operator> <value>
```

For example `env == prod`, `tier != test`, `name =~ "^log-"`.

### Operators

| Operator | Name | Matches when the label is... |
|---|---|---|
| `==` | equality | present **and** its value equals `value` |
| `!=` | inequality | **not** (present and equal) - see [missing-label semantics](#missing-label-semantics) |
| `=~` | regex | present **and** its value matches the regex `value` |
| `^=` | prefix | present **and** its value starts with `value` |
| `$=` | suffix | present **and** its value ends with `value` |

All comparisons are **case-sensitive** and operate on the raw label value as a
UTF-8 string. There is no numeric or date-aware comparison - everything is a
string test. (Use `^=` / `$=` / `=~` for structured values, e.g.
`build $= -rc1`.)

### Label names

A label name is the left side of a condition. Allowed characters:

```
A-Z  a-z  0-9  -  _  .
```

Names may not contain spaces or other punctuation. Examples: `env`,
`team-name`, `app.version`, `build_id`.

> Label names are stored lowercased by the daemon when set, so write them
> lowercase in queries (`env`, not `Env`).

### Values: bare vs quoted

The right side of a condition is a **value**. It can be written two ways:

**Bare** - no quotes. A bare value runs from the operator up to the next
whitespace or closing parenthesis `)`. Bare values may contain most punctuation
(including `=`, `-`, `/`, `:`, `.`):

```
env == prod
path ^= /var/log
build $= -rc1
```

**Quoted** - wrapped in double quotes `"..."`. Use quotes when the value
contains a **space**, a closing **parenthesis**, or would otherwise be
ambiguous. Everything between the quotes is taken literally:

```
title == "quarterly report"
note   =~ "draft (v2)"
```

Notes and limitations:

- **The empty value** can only be written quoted: `name == ""` matches a label
  that is present with an empty string value.
- **No escape sequences.** There is no `\"` - a value that itself contains a
  double-quote character cannot currently be expressed.
- Quoting does not change matching semantics; `env == prod` and `env == "prod"`
  are identical.

### Missing-label semantics

When the named label is **absent** from an object, each operator behaves as:

| Operator | Result on a missing label |
|---|---|
| `==` | `false` |
| `=~` | `false` |
| `^=` | `false` |
| `$=` | `false` |
| `!=` | `true` |

`!=` is the only operator that is **true** for an absent label. Read
`tier != test` as "objects that are not explicitly `tier=test`" - which
includes objects with no `tier` label at all. To require the label *and* a
differing value, combine with an existence-style test, e.g.
`tier ^= "" and tier != test` (`tier ^= ""` is true only when `tier` is present,
since every string starts with the empty string).

---

## Combining conditions

### Operators and precedence

| Combinator | Aliases | Arity |
|---|---|---|
| `or` | `\|\|` | binary |
| `and` | `&&` | binary |
| `not` | `!` | unary prefix |

Keywords are **case-insensitive** (`AND`, `And`, `and` are equivalent). The
symbolic forms `&&`, `\|\|`, `!` are exact synonyms.

Precedence, from **lowest** (binds loosest) to **highest** (binds tightest):

```
or   <   and   <   not
```

So this query:

```
a == 1 or b == 1 and c == 1
```

parses as `a == 1 or (b == 1 and c == 1)` - the `and` binds tighter than the
`or`. Both binary operators are **left-associative**:
`a or b or c` == `(a or b) or c`.

### Parentheses

Use `( ... )` to override precedence or group for clarity:

```
(env == prod or env == stage) and tier != test
```

Parentheses may nest arbitrarily.

### `not`

`not` (or `!`) negates the expression that follows it - a single condition or a
parenthesized group:

```
not env == prod
not (tier == test or tier == dev)
```

`not` binds tighter than `and`/`or`, so `not a == 1 and b == 2` is
`(not a == 1) and b == 2`. Wrap in parens to negate a whole clause:
`not (a == 1 and b == 2)`.

---

## Regular expressions

The `=~` operator matches the label value against a regular expression using
Rust's [`regex`](https://docs.rs/regex) crate.

- **Unanchored by default.** `env =~ prod` matches any value *containing*
  `prod` - including `production` and `nonprod`. Anchor explicitly with `^` and
  `$`: `env =~ "^prod$"` for an exact match (equivalent to `env == prod`).
- **Syntax** is the standard `regex`-crate dialect: character classes
  `[a-z]`, alternation `a|b`, quantifiers `* + ? {n,m}`, groups `( )`, anchors
  `^ $`, etc.
- **No backreferences or lookaround.** The engine guarantees linear-time
  matching, so these features are unavailable by design (this is also why a
  hostile regex cannot cause catastrophic backtracking).
- Regexes are **compiled when the query is parsed**. An invalid pattern is
  rejected up front with a `400` error rather than silently matching nothing.

Examples:

```
name =~ "^log-[0-9]{4}-"      # keys-style label beginning log-YYYY-
team =~ "infra|sre|platform"  # any of three teams
ext  =~ "\\.(jpg|png|gif)$"   # value ends with an image extension
```

> Quote regexes that contain spaces, `)`, or shell metacharacters. In a shell,
> wrap the whole `--query` argument in single quotes so the shell does not touch
> the backslashes or `$`.

---

## Whitespace and tokenization rules

Understanding how the query is tokenized avoids surprises:

- **Whitespace is required around the symbolic combinators** `&&`, `||`, `!`
  and around keywords `and`/`or`/`not` - because a bare value greedily consumes
  non-space characters. `env==prod&&tier==web` is parsed as a single condition
  with the bare value `prod&&tier==web`, **not** as two conditions. Write
  `env == prod && tier == web` (or use `and`).
- Whitespace **around the condition operators** (`==`, `!=`, `=~`, `^=`, `$=`)
  is optional: `env==prod` and `env == prod` are the same. Spaces are
  recommended for readability.
- A bare value ends at the first space or `)`. To include either, quote the
  value.
- Leading/trailing whitespace in the whole query is ignored.

---

## Search scope and parameters

`GET /api/v1/search` query-string parameters:

| Name | Type | Default | Meaning |
|---|---|---|---|
| `q` | string | *(required)* | The query expression (this document) |
| `bucket` | string | all buckets | Restrict the search to one bucket |
| `prefix` | string | - | Only consider objects whose key starts with this prefix |
| `after` | string | - | Opaque pagination cursor (see [Pagination](#pagination)) |
| `limit` | integer | 1000 | Max items per page; capped at 10000 |

How the CLI maps the remote path to these:

| CLI path argument | `bucket` | `prefix` | Scope |
|---|---|---|---|
| `alias/` | *(none)* | *(none)* | every bucket on the server |
| `alias/photos` | `photos` | *(none)* | one bucket |
| `alias/photos/2024/` | `photos` | `2024/` | one bucket, keys under `2024/` |

`prefix` and `bucket` are applied **in addition to** the label query - an object
must match the query *and* fall within the scope.

---

## Pagination

Results are sorted by `(bucket, key)` and returned a page at a time. The
response carries a `next` field:

- `next: null` - this is the final page.
- `next: "<cursor>"` - more results exist. Pass the value back as `after` to
  fetch the next page.

The cursor is **opaque** - do not parse or construct it; only echo back what the
server returned. (Internally it encodes the last `(bucket, key)` pair, which is
why it differs from the plain-key cursor used by `GET /{bucket}/`.)

The CLI command auto-paginates: it follows `next` until exhausted and prints the
full result set.

Manual pagination loop over HTTP:

```sh
cursor=""
while :; do
  page=$(curl -s -H "Authorization: Bearer $TOKEN" --get \
    "https://y2qd.example/api/v1/search" \
    --data-urlencode 'q=env == prod' \
    ${cursor:+--data-urlencode "after=$cursor"})
  echo "$page" | jq -c '.items[] | {bucket, key}'
  cursor=$(echo "$page" | jq -r '.next // empty')
  [ -z "$cursor" ] && break
done
```

---

## Errors

| Status | Cause |
|---|---|
| `400` | The query failed to parse, or contained an invalid regex, or `bucket` is invalid. The response body's `error` field describes what went wrong. |
| `401` | Missing or invalid bearer token. |
| `500` | Index or storage failure. |

The daemon is the single source of truth for query validity; the CLI surfaces a
`400` as a non-zero exit with the server's message. Examples that produce `400`:

```
env ==                 # missing value
== prod                # missing label name
env =~ "["             # invalid regex (unclosed character class)
```

---

## Worked examples

```sh
# All production objects that are not test-tier, anywhere on the server
y2q search prod/ --query 'env == prod and tier != test'

# Either prod or stage, excluding anything explicitly marked ephemeral
y2q search prod/ --query '(env == prod or env == stage) and not lifecycle == ephemeral'

# Objects owned by anyone on the infra/sre teams whose name begins with "log-"
y2q search prod/logs --query 'team =~ "infra|sre" and name ^= log-'

# Release candidates: build value ends in -rcN
y2q search prod/artifacts --query 'build $= -rc1 or build $= -rc2'

# Has a region label set to something other than us-east, in the cdn bucket
y2q search prod/cdn --query 'region ^= "" and region != us-east'

# Exact-match via regex anchors (same as owner == alice)
y2q search prod/ --query 'owner =~ "^alice$"'
```

HTTP, multi-condition with explicit encoding of the spaces:

```sh
curl -s -H "Authorization: Bearer $TOKEN" --get \
  "https://y2qd.example/api/v1/search" \
  --data-urlencode 'q=(env == prod or env == stage) and tier != test' \
  --data-urlencode 'prefix=2024/' \
  --data-urlencode 'bucket=photos' \
  --data-urlencode 'limit=500'
```

---

## Performance and limits

- Search is a **full scan** of the bucket's (or the whole server's) metadata
  index, evaluating the query against each object's labels. Cost grows with the
  number of indexed objects, not the number of matches. A bucket-scoped or
  prefix-scoped search reads fewer rows than a server-wide one - narrow the
  scope when you can.
- The exact-equality lookup (`lookup_by_label`, used internally elsewhere) has a
  dedicated reverse index; the general query path does not yet use it. A
  label-index fast path for pure-`and`-of-`==` queries is a possible future
  optimization.
- `limit` defaults to 1000 and is capped at 10000 per page; use pagination for
  larger result sets.
- Matching is linear-time in the value length even for regexes, so queries are
  safe to expose to untrusted callers (subject to normal auth).

---

## Formal grammar

The query language is defined by this PEG (the canonical source is
[`crates/y2q-core/src/query/grammar.pest`](../crates/y2q-core/src/query/grammar.pest)):

```pest
WHITESPACE = _{ " " | "\t" | "\r" | "\n" }

query = { SOI ~ expr ~ EOI }

expr = { prefix* ~ primary ~ (infix ~ prefix* ~ primary)* }

infix = _{ and | or }
and   =  { ^"and" | "&&" }
or    =  { ^"or" | "||" }

prefix = _{ not }
not    =  { ^"not" | "!" }

primary = _{ condition | "(" ~ expr ~ ")" }

condition = { ident ~ op ~ value }

op  = _{ eq | ne | re | pre | suf }
eq  =  { "==" }
ne  =  { "!=" }
re  =  { "=~" }
pre =  { "^=" }
suf =  { "$=" }

ident = @{ (ASCII_ALPHANUMERIC | "-" | "_" | ".")+ }

value  = _{ string | bare }
string = ${ "\"" ~ inner ~ "\"" }
inner  = @{ (!"\"" ~ ANY)* }
bare   = @{ (!(WHITESPACE | ")") ~ ANY)+ }
```

Operator precedence and associativity are applied by a Pratt parser, not by the
grammar: `or` (lowest) then `and` then prefix `not` (highest), with both binary
operators left-associative.
