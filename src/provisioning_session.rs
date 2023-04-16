use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_web_actors::ws::{self, CloseReason};
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use bytestring::ByteString;
use log::{debug, error, info};
use omnisette::adi_proxy::IDENTIFIER_LENGTH;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

use crate::{
    provider_instance::ProviderInstance,
    result::{SendServerResult, ServerResult},
    PAYLOAD_LIMIT,
};

const TIMEOUT_CHECK_INTERVAL: Duration = Duration::from_millis(250);
// TODO: allow changing the timeout with a command line argument
const TIMEOUT_DURATION: u64 = 1250; // TODO: adjust to be as small as possible while still not closing on slower connections
const TIMEOUT: Duration = Duration::from_millis(TIMEOUT_DURATION);

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct Identifier {
    pub identifier: String,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct StartProvisioningData {
    pub spim: String,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct EndProvisioningData {
    pub ptm: String,
    pub tk: String,
}

trait ExitContext {
    fn exit(&mut self, res: ServerResult, reason: Option<CloseReason>);
}

impl ExitContext for ws::WebsocketContext<ProvisioningSession> {
    fn exit(&mut self, res: ServerResult, reason: Option<CloseReason>) {
        self.res(res);
        self.close(reason);
        self.terminate();
    }
}

#[derive(Debug)]
enum ProvisioningSessionState {
    Wait,
    WaitingForIdentifier,
    WaitingForStartProvisioningData,
    CurrentlyStartingProvisioning,
    WaitingForEndProvisioningData,
    CurrentlyEndingProvisioning,
}

pub struct ProvisioningSession {
    last_action: Instant,
    provider: Option<ProviderInstance>,
    state: ProvisioningSessionState,
    session: u32,
}

impl ProvisioningSession {
    pub fn new() -> Self {
        Self {
            last_action: Instant::now(),
            provider: None,
            state: ProvisioningSessionState::Wait,
            session: 0,
        }
    }

    fn start_timeout_check(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(TIMEOUT_CHECK_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.last_action) >= TIMEOUT {
                error!("Disconnecting because of timeout");
                ctx.exit(ServerResult::Timeout, None);
            }
        });
    }

    fn handle_identifier(&mut self, ctx: &mut <Self as Actor>::Context, text: ByteString) {
        self.state = ProvisioningSessionState::Wait; // ensure this method doesn't get called while it's executing
        info!("Handling identifier");
        match serde_json::from_str::<Identifier>(text.to_string().as_str()) {
            Ok(d) => {
                let identifier = match base64_engine.decode(d.identifier) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("Got error decoding identifier: {e:?}");
                        ctx.exit(
                            ServerResult::InvalidIdentifier {
                                message: format!("Couldn't decode identifier: {e:?}"),
                            },
                            None,
                        );

                        return;
                    }
                };

                if identifier.len() != IDENTIFIER_LENGTH {
                    let message = format!("Identifier must be {IDENTIFIER_LENGTH} bytes long");

                    error!("{message}");
                    ctx.exit(ServerResult::InvalidIdentifier { message }, None);

                    return;
                }

                self.provider = match ProviderInstance::new(
                    Some(identifier.as_slice().try_into().unwrap()),
                    None,
                ) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        error!("Got error creating ProviderInstance: {e:?}");
                        ctx.exit(
                            ServerResult::InvalidIdentifier {
                                message: format!("Couldn't create ProviderInstance: {e:?}"),
                            },
                            None,
                        );

                        return;
                    }
                };
                self.state = ProvisioningSessionState::WaitingForStartProvisioningData;
                info!("Telling client to give start provisioning data");
                ctx.res(ServerResult::GiveStartProvisioningData);
            }
            Err(e) => {
                error!("Got error receiving Identifier: {e:?}");
                ctx.exit(
                    ServerResult::InvalidIdentifier {
                        message: format!("Couldn't read input: {e}"),
                    },
                    None,
                );
            }
        }
    }

    fn handle_start_provisioning_data(
        &mut self,
        ctx: &mut <Self as Actor>::Context,
        text: ByteString,
    ) {
        self.state = ProvisioningSessionState::CurrentlyStartingProvisioning;
        info!("Handling start provisioning data");
        match serde_json::from_str::<StartProvisioningData>(text.to_string().as_str()) {
            Ok(d) => {
                if d.spim.len() > PAYLOAD_LIMIT {
                    let message = format!("spim is over the payload limit ({PAYLOAD_LIMIT} bytes)");

                    error!("{message}");
                    ctx.exit(ServerResult::StartProvisioningError { message }, None);

                    return;
                }

                let spim = match base64_engine.decode(d.spim) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("Got error getting spim: {e:?}");
                        ctx.exit(
                            ServerResult::StartProvisioningError {
                                message: format!("Couldn't decode spim: {e:?}"),
                            },
                            None,
                        );

                        return;
                    }
                };

                info!("Starting provisioning");
                match self
                    .provider
                    .as_mut()
                    .unwrap() // should be safe to unwrap since it must be Some for this function to ever be called
                    .start_provisioning(spim.as_slice())
                {
                    Ok(r) => {
                        self.session = r.session;
                        self.state = ProvisioningSessionState::WaitingForEndProvisioningData;
                        info!("Telling client to give end provisioning data");
                        ctx.res(ServerResult::GiveEndProvisioningData {
                            cpim: base64_engine.encode(r.cpim),
                        });
                    }
                    Err(e) => {
                        error!("Got error starting provisioning: {e:?}");
                        ctx.exit(
                            ServerResult::StartProvisioningError {
                                message: format!("Couldn't start provisioning: {e:?}"),
                            },
                            None,
                        );
                    }
                }
            }
            Err(e) => {
                error!("Got error receiving StartProvisioningData: {e:?}");
                ctx.exit(
                    ServerResult::StartProvisioningError {
                        message: format!("Couldn't read input: {e}"),
                    },
                    None,
                );
            }
        }
    }

    fn handle_end_provisioning_data(
        &mut self,
        ctx: &mut <Self as Actor>::Context,
        text: ByteString,
    ) {
        self.state = ProvisioningSessionState::CurrentlyEndingProvisioning;
        info!("Handling end provisioning data");
        match serde_json::from_str::<EndProvisioningData>(text.to_string().as_str()) {
            Ok(d) => {
                if d.ptm.len() > PAYLOAD_LIMIT {
                    let message = format!("ptm is over the payload limit ({PAYLOAD_LIMIT} bytes)");

                    error!("{message}");
                    ctx.exit(ServerResult::EndProvisioningError { message }, None);

                    return;
                }

                if d.tk.len() > PAYLOAD_LIMIT {
                    let message = format!("tk is over the payload limit ({PAYLOAD_LIMIT} bytes)");

                    error!("{message}");
                    ctx.exit(ServerResult::EndProvisioningError { message }, None);

                    return;
                }

                let ptm = match base64_engine.decode(d.ptm) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("Got error decoding ptm: {e:?}");
                        ctx.exit(
                            ServerResult::EndProvisioningError {
                                message: format!("Couldn't decode ptm: {e:?}"),
                            },
                            None,
                        );

                        return;
                    }
                };

                let tk = match base64_engine.decode(d.tk) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("Got error decoding tk: {e:?}");
                        ctx.exit(
                            ServerResult::EndProvisioningError {
                                message: format!("Couldn't decode tk: {e:?}"),
                            },
                            None,
                        );

                        return;
                    }
                };

                info!("Ending provisioning");
                match self
                    .provider
                    .as_mut()
                    .unwrap() // should be safe to unwrap since it must be Some for this function to ever be called
                    .end_provisioning(self.session, ptm.as_slice(), tk.as_slice())
                {
                    Ok(adi_pb) => {
                        info!("Exiting with success");
                        self.session = 0; // don't destroy the session if it succeeded
                        ctx.exit(
                            ServerResult::ProvisioningSuccess {
                                adi_pb: base64_engine.encode(adi_pb),
                            },
                            None,
                        );
                    }
                    Err(e) => {
                        error!("Got error ending provisioning: {e:?}");
                        ctx.exit(
                            ServerResult::EndProvisioningError {
                                message: format!("Couldn't end provisioning: {e:?}"),
                            },
                            None,
                        );
                    }
                }
            }
            Err(e) => {
                error!("Got error receiving EndProvisioningData: {e:?}");
                ctx.exit(
                    ServerResult::EndProvisioningError {
                        message: format!("Couldn't read input: {e}"),
                    },
                    None,
                );
            }
        }
    }
}

impl Actor for ProvisioningSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.state = ProvisioningSessionState::WaitingForIdentifier;
        self.start_timeout_check(ctx);
        info!("Telling client to give identifier");
        ctx.res(ServerResult::GiveIdentifier);
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        info!("Cleaning up");
        // yes, it would be better to use `let Some(provider) = self.provider` but if let chains currently aren't stable and nesting the if let in another if statement means duplicate code because of the skip log
        if self.session != 0 && self.provider.is_some() {
            match self
                .provider
                .as_mut()
                .unwrap() // safe to unwrap since we check if it is Some
                .destroy_provisioning_session(self.session)
            {
                Ok(_) => info!("Destroyed provisioning session"),
                Err(e) => error!("Failed to destory provisioning session: {e:?}"),
            }
        } else {
            info!("Skipping destory provisioning session");
        }
        self.provider = None;
        info!("Cleanup complete!");
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ProvisioningSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Text(text)) => {
                // Only update last_action for actual actions
                match self.state {
                    ProvisioningSessionState::WaitingForIdentifier
                    | ProvisioningSessionState::WaitingForStartProvisioningData
                    | ProvisioningSessionState::WaitingForEndProvisioningData => {
                        debug!("Updating last_action because state is {:?}", self.state);
                        self.last_action = Instant::now()
                    }
                    _ => {}
                }

                match self.state {
                    ProvisioningSessionState::Wait => ctx.res(ServerResult::Wait),

                    ProvisioningSessionState::WaitingForIdentifier => {
                        self.handle_identifier(ctx, text)
                    }

                    ProvisioningSessionState::WaitingForStartProvisioningData => {
                        self.handle_start_provisioning_data(ctx, text)
                    }

                    ProvisioningSessionState::CurrentlyStartingProvisioning => {
                        ctx.res(ServerResult::CurrentlyStartingProvisioning)
                    }

                    ProvisioningSessionState::WaitingForEndProvisioningData => {
                        self.handle_end_provisioning_data(ctx, text)
                    }

                    ProvisioningSessionState::CurrentlyEndingProvisioning => {
                        ctx.res(ServerResult::CurrentlyEndingProvisioning)
                    }
                }
            }

            Ok(ws::Message::Close(reason)) => {
                info!("Closing per client request");
                ctx.exit(ServerResult::ClosingPerRequest, reason)
            }

            Ok(_) => {
                error!("The client tried to give us something other than text");
                ctx.exit(ServerResult::TextOnly, None)
            }

            Err(e) => {
                error!("There was a Websocket error: {e}");
                ctx.exit(
                    ServerResult::WebsocketError {
                        message: format!("{e}"),
                    },
                    None,
                )
            }
        }
    }
}
