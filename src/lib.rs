//! Shared mechanics for model-backed judge adapters.
//!
//! This crate deliberately owns no Mind semantics. Concrete adapters provide
//! domain contracts and prompt/config data; `judge` only names provider calls,
//! provider authorization references, and reusable client mechanics.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("retry policy requires at least one attempt")]
    EmptyRetryPolicy,

    #[error("judge value is empty")]
    EmptyValue,

    #[error("provider call failed: {0}")]
    ProviderCall(String),

    #[error("secret source is unsupported: {0}")]
    SecretSourceUnsupported(String),

    #[error("secret source is unavailable: {0}")]
    SecretSourceUnavailable(String),

    #[error("provider command failed: {0}")]
    ProviderCommand(String),

    #[cfg(feature = "live-provider")]
    #[error("provider endpoint returned malformed response: {0}")]
    ProviderResponse(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointUrl(String);

impl EndpointUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderName(String);

impl ProviderName {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderModelName(String);

impl ProviderModelName {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
}

impl ReasoningEffort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretSourceReference(String);

impl SecretSourceReference {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretSourceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretSourceReference(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionAuthorizationSourceReference(String);

impl SessionAuthorizationSourceReference {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionAuthorizationSourceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAuthorizationSourceReference(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ProviderAuthorization {
    NoSecret,
    BearerSecretSource(SecretSourceReference),
    ExternalSession(SessionAuthorizationSourceReference),
}

impl ProviderAuthorization {
    pub fn no_secret() -> Self {
        Self::NoSecret
    }

    pub fn bearer_secret_source(reference: SecretSourceReference) -> Self {
        Self::BearerSecretSource(reference)
    }

    pub fn external_session(reference: SessionAuthorizationSourceReference) -> Self {
        Self::ExternalSession(reference)
    }

    pub fn resolve(
        &self,
        resolver: &dyn ProviderSecretResolver,
    ) -> Result<ResolvedProviderAuthorization, Error> {
        match self {
            Self::NoSecret => Ok(ResolvedProviderAuthorization::NoSecret),
            Self::BearerSecretSource(reference) => resolver
                .resolve(reference)
                .map(ResolvedProviderAuthorization::BearerSecret),
            Self::ExternalSession(reference) => Ok(ResolvedProviderAuthorization::ExternalSession(
                reference.clone(),
            )),
        }
    }
}

impl fmt::Debug for ProviderAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSecret => formatter.write_str("NoSecret"),
            Self::BearerSecretSource(reference) => formatter
                .debug_tuple("BearerSecretSource")
                .field(reference)
                .finish(),
            Self::ExternalSession(reference) => formatter
                .debug_tuple("ExternalSession")
                .field(reference)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransientBearerSecret(String);

impl TransientBearerSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for TransientBearerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransientBearerSecret(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedProviderAuthorization {
    NoSecret,
    BearerSecret(TransientBearerSecret),
    ExternalSession(SessionAuthorizationSourceReference),
}

impl ResolvedProviderAuthorization {
    pub fn no_secret() -> Self {
        Self::NoSecret
    }

    pub fn bearer_secret(secret: TransientBearerSecret) -> Self {
        Self::BearerSecret(secret)
    }

    pub fn external_session(reference: SessionAuthorizationSourceReference) -> Self {
        Self::ExternalSession(reference)
    }

    pub fn bearer_secret_value(&self) -> Option<&str> {
        match self {
            Self::BearerSecret(secret) => Some(secret.as_str()),
            Self::NoSecret | Self::ExternalSession(_) => None,
        }
    }
}

impl fmt::Debug for ResolvedProviderAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSecret => formatter.write_str("NoSecret"),
            Self::BearerSecret(_) => formatter.write_str("BearerSecret(<redacted>)"),
            Self::ExternalSession(_) => formatter.write_str("ExternalSession(<redacted>)"),
        }
    }
}

pub trait ProviderSecretResolver: Send + Sync {
    fn resolve(&self, reference: &SecretSourceReference) -> Result<TransientBearerSecret, Error>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentSecretResolver;

impl ProviderSecretResolver for EnvironmentSecretResolver {
    fn resolve(&self, reference: &SecretSourceReference) -> Result<TransientBearerSecret, Error> {
        let Some(name) = reference.as_str().strip_prefix("env:") else {
            return Err(Error::SecretSourceUnsupported(
                reference.as_str().to_owned(),
            ));
        };
        if name.is_empty() {
            return Err(Error::EmptyValue);
        }
        std::env::var(name)
            .map_err(|_| Error::SecretSourceUnavailable(reference.as_str().to_owned()))
            .and_then(TransientBearerSecret::new)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderMessage {
    role: ProviderMessageRole,
    text: String,
}

impl ProviderMessage {
    pub fn system(text: impl Into<String>) -> Self {
        Self::new(ProviderMessageRole::System, text)
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self::new(ProviderMessageRole::User, text)
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self::new(ProviderMessageRole::Assistant, text)
    }

    pub fn new(role: ProviderMessageRole, text: impl Into<String>) -> Self {
        Self {
            role,
            text: text.into(),
        }
    }

    pub fn role(&self) -> ProviderMessageRole {
        self.role
    }

    pub fn text(&self) -> &str {
        self.text.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderMessageRole {
    System,
    User,
    Assistant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCallRequest {
    provider_name: ProviderName,
    model_name: ProviderModelName,
    reasoning_effort: Option<ReasoningEffort>,
    authorization: ResolvedProviderAuthorization,
    messages: Vec<ProviderMessage>,
}

impl ProviderCallRequest {
    pub fn new(
        provider_name: ProviderName,
        model_name: ProviderModelName,
        reasoning_effort: Option<ReasoningEffort>,
        authorization: ResolvedProviderAuthorization,
        messages: Vec<ProviderMessage>,
    ) -> Self {
        Self {
            provider_name,
            model_name,
            reasoning_effort,
            authorization,
            messages,
        }
    }

    pub fn provider_name(&self) -> &ProviderName {
        &self.provider_name
    }

    pub fn model_name(&self) -> &ProviderModelName {
        &self.model_name
    }

    pub fn reasoning_effort(&self) -> Option<ReasoningEffort> {
        self.reasoning_effort
    }

    pub fn authorization(&self) -> &ResolvedProviderAuthorization {
        &self.authorization
    }

    pub fn messages(&self) -> &[ProviderMessage] {
        self.messages.as_slice()
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

pub trait ProviderClient: Send + Sync {
    fn call(&self, request: ProviderCallRequest) -> Result<ProviderCallReply, Error>;
}

impl<Client> ProviderClient for Box<Client>
where
    Client: ProviderClient + ?Sized,
{
    fn call(&self, request: ProviderCallRequest) -> Result<ProviderCallReply, Error> {
        self.as_ref().call(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureProviderClient {
    reply: ProviderCallReply,
}

impl FixtureProviderClient {
    pub fn new(reply: ProviderCallReply) -> Self {
        Self { reply }
    }

    pub fn from_text(text: impl Into<String>) -> Self {
        Self::new(ProviderCallReply::new(text, Vec::new()))
    }
}

impl ProviderClient for FixtureProviderClient {
    fn call(&self, _request: ProviderCallRequest) -> Result<ProviderCallReply, Error> {
        Ok(self.reply.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAiCodexProviderClient {
    command: PathBuf,
}

impl OpenAiCodexProviderClient {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

impl ProviderClient for OpenAiCodexProviderClient {
    fn call(&self, request: ProviderCallRequest) -> Result<ProviderCallReply, Error> {
        OpenAiCodexInvocation::from_request(&self.command, request)?.execute()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenAiCodexInvocation {
    command: PathBuf,
    arguments: Vec<OsString>,
}

impl OpenAiCodexInvocation {
    fn from_request(command: &Path, request: ProviderCallRequest) -> Result<Self, Error> {
        if request.provider_name().as_str() != "openai-codex" {
            return Err(Error::ProviderCall(
                "OpenAI Codex client requires provider openai-codex".to_owned(),
            ));
        }
        let mut arguments = vec![
            OsString::from("exec"),
            OsString::from("--ephemeral"),
            OsString::from("--skip-git-repo-check"),
            OsString::from("--ignore-rules"),
            OsString::from("--sandbox"),
            OsString::from("read-only"),
            OsString::from("--model"),
            OsString::from(request.model_name().as_str()),
        ];
        if let Some(reasoning_effort) = request.reasoning_effort() {
            arguments.push(OsString::from("--config"));
            arguments.push(OsString::from(format!(
                "model_reasoning_effort=\"{}\"",
                reasoning_effort.as_str()
            )));
        }
        arguments.push(OsString::from(Self::prompt_from_messages(
            request.messages(),
        )));
        Ok(Self {
            command: command.to_path_buf(),
            arguments,
        })
    }

    fn prompt_from_messages(messages: &[ProviderMessage]) -> String {
        messages
            .iter()
            .map(|message| match message.role() {
                ProviderMessageRole::System => format!("[system]\n{}", message.text()),
                ProviderMessageRole::User => format!("[user]\n{}", message.text()),
                ProviderMessageRole::Assistant => format!("[assistant]\n{}", message.text()),
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    fn execute(self) -> Result<ProviderCallReply, Error> {
        let output = Command::new(&self.command)
            .args(&self.arguments)
            .output()
            .map_err(|_| Error::ProviderCommand("OpenAI Codex command unavailable".to_owned()))?;
        if !output.status.success() {
            return Err(Error::ProviderCommand(
                "OpenAI Codex command rejected the provider request".to_owned(),
            ));
        }
        let output_text = String::from_utf8(output.stdout).map_err(|_| {
            Error::ProviderCommand("OpenAI Codex command returned non-UTF-8 output".to_owned())
        })?;
        if output_text.trim().is_empty() {
            return Err(Error::ProviderCommand(
                "OpenAI Codex command returned empty output".to_owned(),
            ));
        }
        Ok(ProviderCallReply::new(output_text, Vec::new()))
    }
}

#[cfg(feature = "live-provider")]
#[derive(Clone, Debug)]
pub struct OpenAiCompatibleProviderClient {
    endpoint: EndpointUrl,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "live-provider")]
impl OpenAiCompatibleProviderClient {
    pub fn new(endpoint: EndpointUrl) -> Self {
        Self {
            endpoint,
            client: reqwest::blocking::Client::new(),
        }
    }
}

#[cfg(feature = "live-provider")]
impl ProviderClient for OpenAiCompatibleProviderClient {
    fn call(&self, request: ProviderCallRequest) -> Result<ProviderCallReply, Error> {
        let endpoint = format!(
            "{}/chat/completions",
            self.endpoint.as_str().trim_end_matches('/')
        );
        let mut builder = self
            .client
            .post(endpoint)
            .json(&OpenAiCompatibleRequest::from(&request));
        if let Some(secret) = request.authorization().bearer_secret_value() {
            builder = builder.bearer_auth(secret);
        }
        let response = builder
            .send()
            .map_err(|error| Error::ProviderCall(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::ProviderCall(format!(
                "provider returned HTTP {}",
                response.status()
            )));
        }
        let response = response
            .json::<OpenAiCompatibleResponse>()
            .map_err(|error| Error::ProviderResponse(error.to_string()))?;
        response.into_reply()
    }
}

#[cfg(feature = "live-provider")]
#[derive(serde::Serialize)]
struct OpenAiCompatibleRequest<'request> {
    model: &'request str,
    messages: Vec<OpenAiCompatibleMessage<'request>>,
}

#[cfg(feature = "live-provider")]
impl<'request> From<&'request ProviderCallRequest> for OpenAiCompatibleRequest<'request> {
    fn from(request: &'request ProviderCallRequest) -> Self {
        Self {
            model: request.model_name().as_str(),
            messages: request
                .messages()
                .iter()
                .map(OpenAiCompatibleMessage::from)
                .collect(),
        }
    }
}

#[cfg(feature = "live-provider")]
#[derive(serde::Serialize)]
struct OpenAiCompatibleMessage<'message> {
    role: &'static str,
    content: &'message str,
}

#[cfg(feature = "live-provider")]
impl<'message> From<&'message ProviderMessage> for OpenAiCompatibleMessage<'message> {
    fn from(message: &'message ProviderMessage) -> Self {
        let role = match message.role() {
            ProviderMessageRole::System => "system",
            ProviderMessageRole::User => "user",
            ProviderMessageRole::Assistant => "assistant",
        };
        Self {
            role,
            content: message.text(),
        }
    }
}

#[cfg(feature = "live-provider")]
#[derive(serde::Deserialize)]
struct OpenAiCompatibleResponse {
    choices: Vec<OpenAiCompatibleChoice>,
}

#[cfg(feature = "live-provider")]
impl OpenAiCompatibleResponse {
    fn into_reply(self) -> Result<ProviderCallReply, Error> {
        let text = self
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content)
            .ok_or_else(|| Error::ProviderResponse("missing first choice".to_owned()))?;
        Ok(ProviderCallReply::new(text, Vec::new()))
    }
}

#[cfg(feature = "live-provider")]
#[derive(serde::Deserialize)]
struct OpenAiCompatibleChoice {
    message: OpenAiCompatibleChoiceMessage,
}

#[cfg(feature = "live-provider")]
#[derive(serde::Deserialize)]
struct OpenAiCompatibleChoiceMessage {
    content: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let reference = SecretSourceReference::unchecked("env:API_KEY");
        let authorization = ProviderAuthorization::bearer_secret_source(reference.clone());
        let resolved = ResolvedProviderAuthorization::bearer_secret(
            TransientBearerSecret::new("secret").unwrap(),
        );

        assert_eq!(
            format!("{authorization:?}"),
            "BearerSecretSource(SecretSourceReference(<redacted>))"
        );
        assert_eq!(format!("{resolved:?}"), "BearerSecret(<redacted>)");
        assert_eq!(
            format!("{reference:?}"),
            "SecretSourceReference(<redacted>)"
        );
    }

    #[test]
    fn fixture_provider_returns_configured_text() {
        let client = FixtureProviderClient::from_text("(Accept None)");
        let request = ProviderCallRequest::new(
            ProviderName::unchecked("fixture"),
            ProviderModelName::unchecked("fixture"),
            None,
            ResolvedProviderAuthorization::no_secret(),
            vec![ProviderMessage::user("judge this")],
        );

        let reply = client.call(request).unwrap();

        assert_eq!(reply.output_text(), "(Accept None)");
    }

    #[test]
    fn codex_invocation_carries_model_and_typed_reasoning_effort() {
        let request = ProviderCallRequest::new(
            ProviderName::unchecked("openai-codex"),
            ProviderModelName::unchecked("gpt-5.6-terra"),
            Some(ReasoningEffort::Medium),
            ResolvedProviderAuthorization::external_session(
                SessionAuthorizationSourceReference::new("codex-login").unwrap(),
            ),
            vec![
                ProviderMessage::system("return a verdict"),
                ProviderMessage::user("judge this candidate"),
            ],
        );

        let invocation =
            OpenAiCodexInvocation::from_request(&PathBuf::from("codex"), request).unwrap();
        let arguments = invocation
            .arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            arguments,
            vec![
                "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--ignore-rules",
                "--sandbox",
                "read-only",
                "--model",
                "gpt-5.6-terra",
                "--config",
                "model_reasoning_effort=\"medium\"",
                "[system]\nreturn a verdict\n\n[user]\njudge this candidate",
            ]
        );
    }
}
