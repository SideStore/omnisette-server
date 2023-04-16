use std::collections::HashMap;

use actix_web::{body::BoxBody, HttpRequest, HttpResponse, Responder};
use actix_web_actors::ws;
use serde::Serialize;

use crate::provisioning_session::ProvisioningSession;

#[derive(Serialize, Debug)]
#[serde(tag = "result")]
pub enum ServerResult {
    // ProvisioningSession messages
    Wait,
    GiveIdentifier,
    GiveStartProvisioningData,
    CurrentlyStartingProvisioning,
    GiveEndProvisioningData { cpim: String },
    CurrentlyEndingProvisioning,
    ProvisioningSuccess { adi_pb: String },

    // ProvisioningSession errors
    TextOnly,
    WebsocketError { message: String },
    ClosingPerRequest,
    Timeout,
    InvalidIdentifier { message: String },
    StartProvisioningError { message: String },
    EndProvisioningError { message: String },

    // HTTP responses
    GetHeadersError { message: String },
    Headers(HashMap<String, String>),
}

impl Responder for ServerResult {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        // GetHeadersError and Headers are currently the only ones we return over HTTP
        if format!("{self:?}").contains("Error") {
            HttpResponse::BadRequest()
        } else {
            HttpResponse::Ok()
        }
        .append_header(("Content-Type", "application/json"))
        .body(serde_json::to_string(&self).unwrap())
    }
}

pub trait SendServerResult {
    fn res(&mut self, res: ServerResult);
}

impl SendServerResult for ws::WebsocketContext<ProvisioningSession> {
    fn res(&mut self, res: ServerResult) {
        self.text(serde_json::to_string(&res).unwrap())
    }
}
