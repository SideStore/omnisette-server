use std::net::IpAddr;

use crate::provider_instance::{ProviderInstance, WrappedProvider};
use crate::provisioning_session::ProvisioningSession;
use crate::result::ServerResult;

use actix_web::error::InternalError;
use actix_web::middleware::{DefaultHeaders, Logger};
use actix_web::{get, post, web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws;
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use clap::Parser;
use log::{error, info, LevelFilter};
use omnisette::adi_proxy::{Identifier, IDENTIFIER_LENGTH};
use parking_lot::Mutex;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};

mod provider_instance;
mod provisioning_session;
mod result;

pub const PAYLOAD_LIMIT: usize = 1536; // this should be more than enough for identifier + adi.pb, both in base64 and wrapped in JSON

#[cfg(test)]
mod tests;

#[get("/")]
async fn index(wrapped: WrappedProvider) -> impl Responder {
    let mut provider = wrapped.lock();

    match provider.get_authentication_headers().await {
        Ok(d) => format!("{d:?}"),
        Err(e) => {
            error!("Couldn't get headers: {e:?}");
            format!("Error: {e:?}")
        }
    }
}

#[get("/provisioning_session")]
async fn provisioning_session_ws(
    req: HttpRequest,
    stream: web::Payload,
    wrapped: WrappedProvider,
) -> Result<HttpResponse, Error> {
    info!("Starting provisioning session");
    ws::start(ProvisioningSession::new(wrapped), &req, stream)
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct HeadersInput {
    identifier: String,
    adi_pb: String,
}

#[post("/get_headers")]
async fn get_headers(wrapped: WrappedProvider, input: web::Json<HeadersInput>) -> impl Responder {
    info!("Getting unique headers");
    let mut provider = wrapped.lock();
    let input = input.into_inner();

    let identifier = match base64_engine.decode(input.identifier) {
        Ok(i) => i,
        Err(e) => {
            error!("Got error decoding identifier: {e:?}");
            return ServerResult::GetHeadersError {
                message: format!("Couldn't decode identifier: {e:?}"),
            };
        }
    };
    if identifier.len() != IDENTIFIER_LENGTH {
        return ServerResult::GetHeadersError {
            message: format!("identifier must be {IDENTIFIER_LENGTH} bytes long"),
        };
    }
    let identifier: Identifier = identifier.as_slice().try_into().unwrap();

    let adi_pb = match base64_engine.decode(input.adi_pb) {
        Ok(i) => i,
        Err(e) => {
            error!("Got error decoding adi_pb: {e:?}");
            return ServerResult::GetHeadersError {
                message: format!("Couldn't decode adi_pb: {e:?}"),
            };
        }
    };

    match provider
        .get_authentication_headers_unique(identifier, adi_pb)
        .await
    {
        Ok(d) => {
            info!("Got unique headers");
            ServerResult::Headers(d)
        }
        Err(e) => {
            error!("Couldn't get unique headers: {e:?}");
            ServerResult::GetHeadersError {
                message: format!("Couldn't get headers: {e:?}"),
            }
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[arg(short, long, default_value_t = LevelFilter::Debug, help = "Available options in order of verbosity: Off, Error, Warn, Info, Debug, Trace")]
    log_level: LevelFilter,
    #[arg(short, long, default_value_t = String::from("0.0.0.0"))]
    ip: String,
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: CliArgs = CliArgs::parse();

    let ip: IpAddr = args
        .ip
        .parse()
        .expect("ip should be a valid IPV4 or IPV6 address");

    TermLogger::init(
        args.log_level,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .add_filter_allow_str("omnisette")
            .add_filter_allow_str("android_loader")
            .add_filter_allow_str("actix_web")
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    info!("Starting server");

    HttpServer::new(|| {
        App::new()
            // Create a provider for each thread
            .app_data(web::Data::new(Mutex::new(ProviderInstance::new())))
            .app_data(
                web::JsonConfig::default()
                    .limit(PAYLOAD_LIMIT)
                    .error_handler(|err, req| {
                        let message = format!("{err}");
                        error!("Error when parsing JSON: {}", message);
                        InternalError::from_response(
                            err,
                            // JSON through actix is only used in get_headers, we do it manually for provisioning_session
                            ServerResult::GetHeadersError {
                                message: format!("Error when parsing input: {message}"),
                            }
                            .respond_to(req),
                        )
                        .into()
                    }),
            )
            .wrap(Logger::default())
            .wrap(
                DefaultHeaders::new()
                    .add(("Server", "omnisette-server"))
                    // Standard security headers
                    .add(("X-XSS-Protection", "0"))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .add((
                        "Cross-Origin-Embedder-Policy",
                        "require-corp; report-to=\"default\";",
                    ))
                    .add((
                        "Cross-Origin-Opener-Policy",
                        "same-site; report-to=\"default\";",
                    ))
                    .add(("Cross-Origin-Resource-Policy", "same-site")),
            )
            .service(index)
            .service(provisioning_session_ws)
            .service(get_headers)
    })
    .bind((ip, args.port))?
    .run()
    .await
}
