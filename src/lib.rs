//! Shared mechanics for model-backed judge adapters.
//!
//! This crate deliberately owns no Mind semantics. It is the future home for
//! provider/proxy calls, secret-source references, NOTA projection helpers,
//! diagnostics, retry policy, and format-failure handling used by concrete
//! judge adapters.

#![forbid(unsafe_code)]

use std::num::NonZeroUsize;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("retry policy requires at least one attempt")]
    EmptyRetryPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderName(String);

impl ProviderName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderModelName(String);

impl ProviderModelName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretSourceReference(String);

impl SecretSourceReference {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptText(String);

impl PromptText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCallRequest {
    provider_name: ProviderName,
    model_name: ProviderModelName,
    secret_source_reference: SecretSourceReference,
    prompt_text: PromptText,
}

impl ProviderCallRequest {
    pub fn new(
        provider_name: ProviderName,
        model_name: ProviderModelName,
        secret_source_reference: SecretSourceReference,
        prompt_text: PromptText,
    ) -> Self {
        Self {
            provider_name,
            model_name,
            secret_source_reference,
            prompt_text,
        }
    }

    pub fn provider_name(&self) -> &ProviderName {
        &self.provider_name
    }

    pub fn model_name(&self) -> &ProviderModelName {
        &self.model_name
    }

    pub fn secret_source_reference(&self) -> &SecretSourceReference {
        &self.secret_source_reference
    }

    pub fn prompt_text(&self) -> &PromptText {
        &self.prompt_text
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCallReply {
    output_text: String,
    diagnostics: Vec<JudgeDiagnostic>,
}

impl ProviderCallReply {
    pub fn new(output_text: impl Into<String>, diagnostics: Vec<JudgeDiagnostic>) -> Self {
        Self {
            output_text: output_text.into(),
            diagnostics,
        }
    }

    pub fn output_text(&self) -> &str {
        self.output_text.as_str()
    }

    pub fn diagnostics(&self) -> &[JudgeDiagnostic] {
        self.diagnostics.as_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JudgeDiagnostic {
    message: String,
}

impl JudgeDiagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    maximum_attempts: NonZeroUsize,
}

impl RetryPolicy {
    pub fn new(maximum_attempts: usize) -> Result<Self, Error> {
        let maximum_attempts =
            NonZeroUsize::new(maximum_attempts).ok_or(Error::EmptyRetryPolicy)?;
        Ok(Self { maximum_attempts })
    }

    pub fn maximum_attempts(&self) -> NonZeroUsize {
        self.maximum_attempts
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatFailure {
    expected_shape: String,
    received_text: String,
}

impl FormatFailure {
    pub fn new(expected_shape: impl Into<String>, received_text: impl Into<String>) -> Self {
        Self {
            expected_shape: expected_shape.into(),
            received_text: received_text.into(),
        }
    }

    pub fn expected_shape(&self) -> &str {
        self.expected_shape.as_str()
    }

    pub fn received_text(&self) -> &str {
        self.received_text.as_str()
    }
}
