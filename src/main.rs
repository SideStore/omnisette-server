use std::net::IpAddr;
use std::path::PathBuf;

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
use omnisette::adi_proxy::{Identifier, AKD_USER_AGENT, CLIENT_INFO_HEADER, IDENTIFIER_LENGTH};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Serialize;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};

mod provider_instance;
mod provisioning_session;
mod result;

pub const PAYLOAD_LIMIT: usize = 1536; // this should be more than enough for identifier + adi.pb, both in base64 and wrapped in JSON

#[cfg(test)]
mod tests;

#[get("/")]
#[allow(clippy::await_holding_lock)]
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

#[derive(Serialize)]
struct ClientInfo {
    client_info: String,
    user_agent: String,
}

// client info is such a simple response that it's faster just to format at const time instead of using serde_json
// TODO: allow changing the header and user agent with a command line argument
const CLIENT_INFO: &str = const_format::formatcp!(
    "{{\"client_info\":\"{CLIENT_INFO_HEADER}\",\"user_agent\":\"{AKD_USER_AGENT}\"}}"
);

#[get("/v3/client_info")]
async fn client_info() -> impl Responder {
    CLIENT_INFO
}

#[get("/v3/provisioning_session")]
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

#[post("/v3/get_headers")]
#[allow(clippy::await_holding_lock)]
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
    #[arg(long, default_value_t = String::from("0.0.0.0"), help = "IP to bind the HTTP server to.")]
    ip: String,
    #[arg(
        long,
        default_value_t = 80,
        value_name = "PORT",
        help = "Port to bind the HTTP server to."
    )]
    http_port: u16,
    #[arg(
        long,
        default_value_t = 443,
        value_name = "PORT",
        help = "Port to bind the HTTPS server to."
    )]
    https_port: u16,
    #[arg(
        short,
        long,
        value_name = "NUM",
        help = "Number of workers (threads) to start. Defaults to the number of physical CPU cores."
    )]
    workers: Option<usize>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to the private key if you want to serve over HTTPS. The first key will be used, and it must be PKCS8 encoded. Currently only `.pem` is supported.",
        requires = "cert_chain"
    )]
    private_key: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to the certificate chain if you want to serve over HTTPS. Currently only `.pem` is supported.",
        requires = "private_key"
    )]
    cert_chain: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = false,
        help = "If specified, omnisette-server will not bind to the HTTP port, only the HTTPS port.",
        requires = "private_key",
        requires = "cert_chain"
    )]
    skip_http_bind: bool,
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
            .set_thread_level(LevelFilter::Error)
            .add_filter_allow_str("omnisette")
            .add_filter_allow_str("android_loader")
            .add_filter_allow_str("actix_web")
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let mut server = HttpServer::new(|| {
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
                    .add((
                        "Implementation-Version",
                        const_format::formatcp!("omnisette-server {}", env!("CARGO_PKG_VERSION")),
                    ))
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
            .service(client_info)
            .service(provisioning_session_ws)
            .service(get_headers)
    });

    if let Some(num) = args.workers {
        info!("Changing number of workers to {num}");
        server = server.workers(num);
    }

    if let Some(private_key) = args.private_key {
        let cert_chain = args.cert_chain.unwrap();

        info!("Initializing HTTPS");

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder
            .set_private_key_file(private_key, SslFiletype::PEM)
            .expect("bad private key");
        builder
            .set_certificate_chain_file(cert_chain)
            .expect("bad certificate chain");

        info!("Binding to https://{ip}:{}", args.https_port);
        server = server.bind_openssl((ip, args.https_port), builder)?;
    }

    if args.skip_http_bind {
        info!("Skipping HTTP bind")
    } else {
        info!("Binding to http://{ip}:{}", args.http_port);
        server = server.bind((ip, args.http_port))?;
    }

    info!("Starting server");
    server.run().await
}
