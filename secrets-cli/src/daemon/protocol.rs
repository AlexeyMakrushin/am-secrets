use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    #[zeroize(skip)]
    pub v: u32,
    #[zeroize(skip)]
    pub cmd: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_session: Option<String>,
}
impl Request {
    pub fn new(cmd: &'static str, context: Option<String>) -> Self {
        Self { v: PROTOCOL_VERSION, cmd, context, master_key: None, provider_session: None }
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[zeroize(skip)]
    pub v: Option<u32>,
    pub status: String,
    pub master_key: Option<String>,
    pub provider_session: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
    #[zeroize(skip)]
    pub session_active: Option<bool>,
}
