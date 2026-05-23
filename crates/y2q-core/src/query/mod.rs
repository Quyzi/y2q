//! Label search query language.
//!
//! A query is a boolean expression over object labels. Each leaf is a
//! condition `name OP value`, where `OP` is one of:
//!
//! | Syntax | Meaning |
//! |--------|---------|
//! | `name == value` | label present and value equal |
//! | `name != value` | NOT (present and equal) - true when the label is absent |
//! | `name =~ value` | value matches the regex `value` |
//! | `name ^= value` | value starts with `value` |
//! | `name $= value` | value ends with `value` |
//!
//! Leaves combine with `and` / `&&`, `or` / `||`, `not` / `!`, and parentheses.
//! Precedence, lowest to highest: `or` < `and` < `not`.
//!
//! This example is `text`-fenced rather than a runnable doctest on purpose: on
//! the current toolchain, `cargo test --doc` builds one merged harness binary
//! for the whole crate, and that binary crashes at startup when it links the
//! `target-cpu=native` `gxhash` rlib (a rustdoc/cargo bug, not a fault in this
//! code). The example is instead verified by the `doc_example` unit test below.
//!
//! ```text
//! use std::collections::BTreeMap;
//! use y2q_core::LabelQuery;
//!
//! let q = LabelQuery::parse(r#"env == prod and (tier =~ "web.*" or not region $= -dev)"#).unwrap();
//! let mut labels = BTreeMap::new();
//! labels.insert("env".to_owned(), "prod".to_owned());
//! labels.insert("tier".to_owned(), "web1".to_owned());
//! labels.insert("region".to_owned(), "us-east".to_owned());
//! assert!(q.matches(&labels));
//! ```

use crate::Error;
use pest::Parser;
use pest::iterators::{Pair, Pairs};
use pest::pratt_parser::{Assoc, Op, PrattParser};
use pest_derive::Parser;
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Parser)]
#[grammar = "query/grammar.pest"]
struct QueryParser;

static PRATT: LazyLock<PrattParser<Rule>> = LazyLock::new(|| {
    // Lowest precedence first.
    PrattParser::new()
        .op(Op::infix(Rule::or, Assoc::Left))
        .op(Op::infix(Rule::and, Assoc::Left))
        .op(Op::prefix(Rule::not))
});

/// A parsed, ready-to-evaluate label search query.
#[derive(Debug, Clone)]
pub enum LabelQuery {
    /// Both sub-queries must match.
    And(Box<LabelQuery>, Box<LabelQuery>),
    /// Either sub-query may match.
    Or(Box<LabelQuery>, Box<LabelQuery>),
    /// The sub-query must not match.
    Not(Box<LabelQuery>),
    /// A single label condition: `name OP value`.
    Cond {
        /// Label name to inspect.
        name: String,
        /// Comparison applied to the label's value.
        op: MatchOp,
    },
}

/// The comparison side of a label [`condition`](LabelQuery::Cond).
#[derive(Debug, Clone)]
pub enum MatchOp {
    /// Label present and value equals the operand.
    Eq(String),
    /// NOT (present and equal) - also true when the label is absent.
    Ne(String),
    /// Label present and value matches this regex (compiled at parse time).
    Regex(regex::Regex),
    /// Label present and value starts with the operand.
    Prefix(String),
    /// Label present and value ends with the operand.
    Suffix(String),
}

impl LabelQuery {
    /// Parse a query string into an evaluable [`LabelQuery`].
    ///
    /// Regexes are compiled here, so a bad pattern surfaces as a parse error
    /// rather than failing later during evaluation.
    pub fn parse(input: &str) -> Result<LabelQuery, Error> {
        let mut pairs = QueryParser::parse(Rule::query, input).map_err(|e| Error::Query {
            message: e.to_string(),
        })?;
        // `query` -> SOI ~ expr ~ EOI; grab the `expr` child.
        let query = pairs.next().ok_or_else(|| Error::Query {
            message: "empty query".to_owned(),
        })?;
        let expr = query
            .into_inner()
            .find(|p| p.as_rule() == Rule::expr)
            .ok_or_else(|| Error::Query {
                message: "empty query".to_owned(),
            })?;
        build_expr(expr.into_inner())
    }

    /// Evaluate this query against an object's labels.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self {
            LabelQuery::And(a, b) => a.matches(labels) && b.matches(labels),
            LabelQuery::Or(a, b) => a.matches(labels) || b.matches(labels),
            LabelQuery::Not(inner) => !inner.matches(labels),
            LabelQuery::Cond { name, op } => match op {
                MatchOp::Ne(v) => labels.get(name).map(|x| x != v).unwrap_or(true),
                MatchOp::Eq(v) => labels.get(name).is_some_and(|x| x == v),
                MatchOp::Regex(re) => labels.get(name).is_some_and(|x| re.is_match(x)),
                MatchOp::Prefix(v) => labels.get(name).is_some_and(|x| x.starts_with(v)),
                MatchOp::Suffix(v) => labels.get(name).is_some_and(|x| x.ends_with(v)),
            },
        }
    }
}

fn build_expr(pairs: Pairs<Rule>) -> Result<LabelQuery, Error> {
    PRATT
        .map_primary(|primary| match primary.as_rule() {
            Rule::condition => build_condition(primary),
            Rule::expr => build_expr(primary.into_inner()),
            other => Err(Error::Query {
                message: format!("unexpected token: {other:?}"),
            }),
        })
        .map_prefix(|op, rhs| match op.as_rule() {
            Rule::not => Ok(LabelQuery::Not(Box::new(rhs?))),
            other => Err(Error::Query {
                message: format!("unexpected prefix: {other:?}"),
            }),
        })
        .map_infix(|lhs, op, rhs| {
            let lhs = lhs?;
            let rhs = rhs?;
            match op.as_rule() {
                Rule::and => Ok(LabelQuery::And(Box::new(lhs), Box::new(rhs))),
                Rule::or => Ok(LabelQuery::Or(Box::new(lhs), Box::new(rhs))),
                other => Err(Error::Query {
                    message: format!("unexpected operator: {other:?}"),
                }),
            }
        })
        .parse(pairs)
}

fn build_condition(pair: Pair<Rule>) -> Result<LabelQuery, Error> {
    let mut inner = pair.into_inner();
    let name = inner
        .next()
        .ok_or_else(|| Error::Query {
            message: "condition missing label name".to_owned(),
        })?
        .as_str()
        .to_owned();
    let op_pair = inner.next().ok_or_else(|| Error::Query {
        message: "condition missing operator".to_owned(),
    })?;
    let op_rule = op_pair.as_rule();
    let value = inner.next().map(value_str).ok_or_else(|| Error::Query {
        message: "condition missing value".to_owned(),
    })?;

    let op = match op_rule {
        Rule::eq => MatchOp::Eq(value),
        Rule::ne => MatchOp::Ne(value),
        Rule::pre => MatchOp::Prefix(value),
        Rule::suf => MatchOp::Suffix(value),
        Rule::re => MatchOp::Regex(regex::Regex::new(&value).map_err(|e| Error::Query {
            message: format!("invalid regex `{value}`: {e}"),
        })?),
        other => {
            return Err(Error::Query {
                message: format!("unexpected operator: {other:?}"),
            });
        }
    };
    Ok(LabelQuery::Cond { name, op })
}

/// Extract a value operand, unwrapping a quoted string to its raw inner text.
fn value_str(pair: Pair<Rule>) -> String {
    match pair.as_rule() {
        // `string` is a compound-atomic rule wrapping an `inner` token.
        Rule::string => pair
            .into_inner()
            .next()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default(),
        _ => pair.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn equality_and_inequality() {
        let q = LabelQuery::parse("env == prod").unwrap();
        assert!(q.matches(&labels(&[("env", "prod")])));
        assert!(!q.matches(&labels(&[("env", "dev")])));
        assert!(!q.matches(&labels(&[])));

        let q = LabelQuery::parse("env != prod").unwrap();
        assert!(!q.matches(&labels(&[("env", "prod")])));
        assert!(q.matches(&labels(&[("env", "dev")])));
        // Missing label: inequality holds.
        assert!(q.matches(&labels(&[])));
    }

    #[test]
    fn prefix_suffix_regex() {
        let q = LabelQuery::parse("name ^= log-").unwrap();
        assert!(q.matches(&labels(&[("name", "log-2026")])));
        assert!(!q.matches(&labels(&[("name", "app-2026")])));

        let q = LabelQuery::parse("name $= .gz").unwrap();
        assert!(q.matches(&labels(&[("name", "dump.gz")])));
        assert!(!q.matches(&labels(&[("name", "dump.zip")])));

        let q = LabelQuery::parse(r#"env =~ "prod|stage""#).unwrap();
        assert!(q.matches(&labels(&[("env", "stage")])));
        assert!(!q.matches(&labels(&[("env", "dev")])));
    }

    #[test]
    fn precedence_or_below_and() {
        // a or b and c  ==  a or (b and c)
        let q = LabelQuery::parse("a == 1 or b == 1 and c == 1").unwrap();
        assert!(q.matches(&labels(&[("a", "1")])));
        assert!(!q.matches(&labels(&[("b", "1")])));
        assert!(q.matches(&labels(&[("b", "1"), ("c", "1")])));
    }

    #[test]
    fn parens_and_not() {
        let q = LabelQuery::parse("(a == 1 or b == 1) and not c == 1").unwrap();
        assert!(q.matches(&labels(&[("a", "1")])));
        assert!(!q.matches(&labels(&[("a", "1"), ("c", "1")])));
        assert!(!q.matches(&labels(&[("c", "1")])));
    }

    #[test]
    fn symbolic_operators() {
        let q = LabelQuery::parse("a == 1 && (b == 1 || c == 1)").unwrap();
        assert!(q.matches(&labels(&[("a", "1"), ("c", "1")])));
        assert!(!q.matches(&labels(&[("a", "1")])));
    }

    #[test]
    fn bad_syntax_is_error() {
        assert!(matches!(
            LabelQuery::parse("env == "),
            Err(Error::Query { .. })
        ));
        assert!(matches!(
            LabelQuery::parse("== prod"),
            Err(Error::Query { .. })
        ));
    }

    /// Verifies the worked example shown in the module-level docs. The doc
    /// block is `text`-fenced (see the note there) so it cannot run as a
    /// doctest; this test is its executable stand-in - keep the two in sync.
    #[test]
    fn doc_example() {
        let q = LabelQuery::parse(r#"env == prod and (tier =~ "web.*" or not region $= -dev)"#)
            .unwrap();
        let labels = labels(&[("env", "prod"), ("tier", "web1"), ("region", "us-east")]);
        assert!(q.matches(&labels));
    }

    #[test]
    fn bad_regex_is_error() {
        assert!(matches!(
            LabelQuery::parse("env =~ \"[\""),
            Err(Error::Query { .. })
        ));
    }
}
