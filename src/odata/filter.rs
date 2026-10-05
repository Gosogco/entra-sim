//! A parser for the subset of OData `$filter` that Entra accepts and clients actually send.
//!
//! Supported: the comparison operators, `and`/`or`/`not`, parentheses, the `startswith`,
//! `endswith` and `contains` functions, `in` lists, and one level of `any` lambda. That covers
//! what the Terraform `azuread` provider and the Graph SDKs emit.
//!
//! Anything outside the subset is a parse error rather than a silently-ignored filter, because a
//! filter that quietly matches everything is far worse than a clear rejection.

use std::fmt;
use std::iter::Peekable;
use std::str::CharIndices;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Compare {
        left: Operand,
        op: CompareOp,
        right: Operand,
    },
    Call {
        function: Function,
        args: Vec<Operand>,
    },
    /// `field in ('a', 'b')`
    In {
        left: Operand,
        values: Vec<Operand>,
    },
    /// `path/any(v: predicate)`, or `path/any()` to test for a non-empty collection.
    Any {
        path: Vec<String>,
        variable: String,
        predicate: Option<Box<Expr>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function {
    StartsWith,
    EndsWith,
    Contains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    /// A property path, such as `displayName` or `verifiedDomains/name`.
    Path(Vec<String>),
    String(String),
    Number(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse a complete `$filter` expression.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
    };
    let expr = parser.parse_or()?;
    if parser.position != tokens.len() {
        return Err(ParseError(format!(
            "unexpected trailing input in filter at token {}",
            parser.position
        )));
    }
    Ok(expr)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    String(String),
    Number(f64),
    Open,
    Close,
    Comma,
    Slash,
    Colon,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars: Peekable<CharIndices<'_>> = input.char_indices().peekable();

    while let Some(&(index, ch)) = chars.peek() {
        match ch {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::Open);
            }
            ')' => {
                chars.next();
                tokens.push(Token::Close);
            }
            ',' => {
                chars.next();
                tokens.push(Token::Comma);
            }
            '/' => {
                chars.next();
                tokens.push(Token::Slash);
            }
            ':' => {
                chars.next();
                tokens.push(Token::Colon);
            }
            '\'' => {
                // `read_string` consumes the opening quote itself.
                tokens.push(Token::String(read_string(&mut chars, index)?));
            }
            c if c.is_ascii_digit() || c == '-' => {
                tokens.push(Token::Number(read_number(&mut chars)?));
            }
            c if c.is_alphabetic() || c == '_' || c == '@' || c == '$' => {
                tokens.push(Token::Ident(read_ident(&mut chars)));
            }
            other => {
                return Err(ParseError(format!(
                    "unexpected character {other:?} at offset {index} in filter"
                )));
            }
        }
    }
    Ok(tokens)
}

/// Read a single-quoted literal. OData escapes an embedded quote by doubling it.
fn read_string(chars: &mut Peekable<CharIndices<'_>>, start: usize) -> Result<String, ParseError> {
    chars.next(); // opening quote
    let mut out = String::new();
    loop {
        match chars.next() {
            Some((_, '\'')) => {
                if let Some(&(_, '\'')) = chars.peek() {
                    chars.next();
                    out.push('\'');
                } else {
                    return Ok(out);
                }
            }
            Some((_, c)) => out.push(c),
            None => {
                return Err(ParseError(format!(
                    "unterminated string literal starting at offset {start} in filter"
                )));
            }
        }
    }
}

fn read_number(chars: &mut Peekable<CharIndices<'_>>) -> Result<f64, ParseError> {
    let mut raw = String::new();
    if let Some(&(_, '-')) = chars.peek() {
        chars.next();
        raw.push('-');
    }
    while let Some(&(_, c)) = chars.peek() {
        if c.is_ascii_digit() || c == '.' {
            raw.push(c);
            chars.next();
        } else {
            break;
        }
    }
    raw.parse()
        .map_err(|_| ParseError(format!("{raw:?} is not a valid number in filter")))
}

fn read_ident(chars: &mut Peekable<CharIndices<'_>>) -> String {
    let mut out = String::new();
    while let Some(&(_, c)) = chars.peek() {
        // Property paths may carry dots and dashes, as in OData type casts and extension names.
        if c.is_alphanumeric() || matches!(c, '_' | '.' | '@' | '$' | '-') {
            out.push(c);
            chars.next();
        } else {
            break;
        }
    }
    out
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.position);
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    /// Consume an identifier if it matches `keyword`, case-insensitively as OData allows.
    fn eat_keyword(&mut self, keyword: &str) -> bool {
        match self.peek() {
            Some(Token::Ident(name)) if name.eq_ignore_ascii_case(keyword) => {
                self.position += 1;
                true
            }
            _ => false,
        }
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        match self.next() {
            Some(token) if token == expected => Ok(()),
            Some(token) => Err(ParseError(format!(
                "expected {expected:?} but found {token:?} in filter"
            ))),
            None => Err(ParseError(format!(
                "expected {expected:?} but the filter ended"
            ))),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;
        while self.eat_keyword("or") {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_unary()?;
        while self.eat_keyword("and") {
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if self.eat_keyword("not") {
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Token::Open)) {
            self.expect(&Token::Open)?;
            let inner = self.parse_or()?;
            self.expect(&Token::Close)?;
            return Ok(inner);
        }

        // A function call is an identifier immediately followed by `(`.
        if let Some(Token::Ident(name)) = self.peek()
            && let Some(function) = function_named(name)
            && matches!(self.tokens.get(self.position + 1), Some(Token::Open))
        {
            self.position += 1;
            return self.parse_call(function);
        }

        let left = self.parse_operand()?;

        // `path/any(...)` is a lambda, not a comparison.
        if let Operand::Path(path) = &left
            && matches!(self.peek(), Some(Token::Ident(name)) if name.eq_ignore_ascii_case("any"))
        {
            let path = path.clone();
            self.position += 1;
            return self.parse_any(path);
        }

        if self.eat_keyword("in") {
            return self.parse_in(left);
        }

        let op = match self.next() {
            Some(Token::Ident(name)) => compare_op_named(name).ok_or_else(|| {
                ParseError(format!("{name:?} is not a supported filter operator"))
            })?,
            Some(token) => {
                return Err(ParseError(format!(
                    "expected a comparison operator but found {token:?} in filter"
                )));
            }
            None => {
                return Err(ParseError(
                    "the filter ended where a comparison operator was expected".to_string(),
                ));
            }
        };

        let right = self.parse_operand()?;
        Ok(Expr::Compare { left, op, right })
    }

    fn parse_call(&mut self, function: Function) -> Result<Expr, ParseError> {
        self.expect(&Token::Open)?;
        let mut args = vec![self.parse_operand()?];
        while matches!(self.peek(), Some(Token::Comma)) {
            self.expect(&Token::Comma)?;
            args.push(self.parse_operand()?);
        }
        self.expect(&Token::Close)?;
        if args.len() != 2 {
            return Err(ParseError(format!(
                "{function:?} takes two arguments but got {}",
                args.len()
            )));
        }
        Ok(Expr::Call { function, args })
    }

    fn parse_in(&mut self, left: Operand) -> Result<Expr, ParseError> {
        self.expect(&Token::Open)?;
        let mut values = Vec::new();
        if !matches!(self.peek(), Some(Token::Close)) {
            values.push(self.parse_operand()?);
            while matches!(self.peek(), Some(Token::Comma)) {
                self.expect(&Token::Comma)?;
                values.push(self.parse_operand()?);
            }
        }
        self.expect(&Token::Close)?;
        Ok(Expr::In { left, values })
    }

    fn parse_any(&mut self, path: Vec<String>) -> Result<Expr, ParseError> {
        self.expect(&Token::Open)?;
        // `any()` with no body asks whether the collection has any element at all.
        if matches!(self.peek(), Some(Token::Close)) {
            self.expect(&Token::Close)?;
            return Ok(Expr::Any {
                path,
                variable: String::new(),
                predicate: None,
            });
        }

        let variable = match self.next() {
            Some(Token::Ident(name)) => name.clone(),
            other => {
                return Err(ParseError(format!(
                    "expected a lambda variable in any() but found {other:?}"
                )));
            }
        };
        self.expect(&Token::Colon)?;
        let predicate = self.parse_or()?;
        self.expect(&Token::Close)?;
        Ok(Expr::Any {
            path,
            variable,
            predicate: Some(Box::new(predicate)),
        })
    }

    fn parse_operand(&mut self) -> Result<Operand, ParseError> {
        match self.next() {
            Some(Token::String(value)) => Ok(Operand::String(value.clone())),
            Some(Token::Number(value)) => Ok(Operand::Number(*value)),
            Some(Token::Ident(name)) => {
                if name.eq_ignore_ascii_case("true") {
                    return Ok(Operand::Bool(true));
                }
                if name.eq_ignore_ascii_case("false") {
                    return Ok(Operand::Bool(false));
                }
                if name.eq_ignore_ascii_case("null") {
                    return Ok(Operand::Null);
                }

                let mut path = vec![name.clone()];
                // A trailing `/any` belongs to the lambda, not the path, so stop before it.
                while matches!(self.peek(), Some(Token::Slash))
                    && !matches!(
                        self.tokens.get(self.position + 1),
                        Some(Token::Ident(next)) if next.eq_ignore_ascii_case("any")
                    )
                {
                    self.expect(&Token::Slash)?;
                    match self.next() {
                        Some(Token::Ident(segment)) => path.push(segment.clone()),
                        other => {
                            return Err(ParseError(format!(
                                "expected a property name after '/' but found {other:?}"
                            )));
                        }
                    }
                }
                // Consume the separator in `path/any(...)` so the caller sees `any` next.
                if matches!(self.peek(), Some(Token::Slash)) {
                    self.expect(&Token::Slash)?;
                }
                Ok(Operand::Path(path))
            }
            other => Err(ParseError(format!(
                "expected a value or property name but found {other:?} in filter"
            ))),
        }
    }
}

fn compare_op_named(name: &str) -> Option<CompareOp> {
    match name.to_ascii_lowercase().as_str() {
        "eq" => Some(CompareOp::Eq),
        "ne" => Some(CompareOp::Ne),
        "gt" => Some(CompareOp::Gt),
        "ge" => Some(CompareOp::Ge),
        "lt" => Some(CompareOp::Lt),
        "le" => Some(CompareOp::Le),
        _ => None,
    }
}

fn function_named(name: &str) -> Option<Function> {
    match name.to_ascii_lowercase().as_str() {
        "startswith" => Some(Function::StartsWith),
        "endswith" => Some(Function::EndsWith),
        "contains" => Some(Function::Contains),
        _ => None,
    }
}
