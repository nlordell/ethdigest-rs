//! Procedural macro for Ethereum digests and hashing.
//!
//! See [`ethdigest::digest`](https://docs.rs/ethdigest/latest/ethdigest/macro.digest.html)
//! and [`ethdigest::hash`](https://docs.rs/ethdigest/latest/ethdigest/macro.hash.html)
//! documentation for more information.

extern crate proc_macro;

mod hex;

use proc_macro::{Delimiter, Literal, Span, TokenStream, TokenTree};
use sha3::{Digest as _, Keccak256};
use std::fmt::Write as _;

#[proc_macro]
pub fn digest(input: TokenStream) -> TokenStream {
    match DigestLiteral::generate_digest(input) {
        Ok(digest) => digest.into_tokens(),
        Err(err) => err.into_tokens(),
    }
}

#[proc_macro]
pub fn hash(input: TokenStream) -> TokenStream {
    match DigestLiteral::generate_hash(input) {
        Ok(digest) => digest.into_tokens(),
        Err(err) => err.into_tokens(),
    }
}

struct DigestLiteral([u8; 32]);

impl DigestLiteral {
    fn generate_digest(input: TokenStream) -> Result<Self, CompileError> {
        let input = Input::parse(input)?;

        let bytes = hex::decode(&input.value).map_err(|err| CompileError {
            message: format!("invalid digest literal: {err}"),
            // TODO(nlordell): If the `Span` API changes to allow offseting in
            // the future, we can add more details in the case of bad hex
            // character errors.
            span: Some(input.span),
        })?;

        Ok(Self(bytes))
    }

    fn generate_hash(input: TokenStream) -> Result<Self, CompileError> {
        let input = Input::parse(input)?;

        let mut hasher = Keccak256::new();
        hasher.update(&input.value);

        Ok(Self(hasher.finalize().into()))
    }

    fn into_tokens(self) -> TokenStream {
        let mut buf = String::new();
        write!(buf, "::ethdigest::Digest(*b\"").unwrap();
        for byte in self.0 {
            write!(buf, "\\x{byte:02x}").unwrap();
        }
        write!(buf, "\")").unwrap();

        buf.parse().unwrap()
    }
}

struct Input {
    value: String,
    span: Span,
}

impl Input {
    fn parse(input: TokenStream) -> Result<Self, CompileError> {
        let mut result = Input {
            value: String::new(),
            span: Span::call_site(),
        };
        ParserState::start().input(input, &mut result)?.end()?;

        Ok(result)
    }
}

enum ParserState {
    String,
    Eof,
}

impl ParserState {
    fn start() -> Self {
        Self::String
    }

    fn input(self, input: TokenStream, result: &mut Input) -> Result<Self, CompileError> {
        input
            .into_iter()
            .try_fold(self, |state, token| state.next(token, result))
    }

    fn next(self, token: TokenTree, result: &mut Input) -> Result<Self, CompileError> {
        match (&self, &token) {
            // Procedural macros invoked from withing `macro_rules!` expansions
            // may be grouped with a `Ø` delimiter (which allows operator
            // precidence to be preserved).
            //
            // See <https://doc.rust-lang.org/stable/proc_macro/enum.Delimiter.html#variant.None>
            (_, TokenTree::Group(g)) if g.delimiter() == Delimiter::None => {
                self.input(g.stream(), result)
            }

            (Self::String, TokenTree::Literal(l)) => match parse_string(l) {
                Some(value) => {
                    result.value = value;
                    result.span = token.span();
                    Ok(Self::Eof)
                }
                None => Err(self.unexpected(Some(token))),
            },

            _ => Err(self.unexpected(Some(token))),
        }
    }

    fn end(self) -> Result<(), CompileError> {
        match self {
            ParserState::Eof => Ok(()),
            _ => Err(self.unexpected(None)),
        }
    }

    fn unexpected(self, token: Option<TokenTree>) -> CompileError {
        let expected = match self {
            ParserState::String => "string literal",
            ParserState::Eof => "<eof>",
        };
        let (value, span) = match token {
            Some(TokenTree::Group(g)) => {
                let delim = match g.delimiter() {
                    Delimiter::Parenthesis => "(",
                    Delimiter::Brace => "{",
                    Delimiter::Bracket => "[",
                    Delimiter::None => "Ø",
                };
                (delim.to_string(), Some(g.span_open()))
            }
            Some(t) => (t.to_string(), Some(t.span())),
            None => ("<eof>".to_owned(), None),
        };

        CompileError {
            message: format!("expected {expected} but found `{value}`"),
            span,
        }
    }
}

struct CompileError {
    message: String,
    span: Option<Span>,
}

impl CompileError {
    fn into_tokens(self) -> TokenStream {
        let error = format!("compile_error!({:?})", self.message)
            .parse::<TokenStream>()
            .unwrap();

        match self.span {
            Some(span) => error
                .into_iter()
                .map(|mut token| {
                    token.set_span(span);
                    token
                })
                .collect(),
            None => error,
        }
    }
}

fn parse_string(literal: &Literal) -> Option<String> {
    Some(
        literal
            .to_string()
            .strip_prefix('"')?
            .strip_suffix('"')?
            .to_owned(),
    )
}
