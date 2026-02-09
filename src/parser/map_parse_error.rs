use crate::parser::error::{ParserError, ParserSourceError};

pub trait MapParserError<T> {
    fn map_parser_error(self, file: &'static str, line: u32) -> Result<T, ParserError>;
}

impl<T, E: Into<ParserSourceError>> MapParserError<T> for Result<T, E> {
    fn map_parser_error(self, file: &'static str, line: u32) -> Result<T, ParserError> {
        self.map_err(|e| ParserError {
            source: e.into(),
            file,
            line,
        })
    }
}
