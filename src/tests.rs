//! WARNING: Lots of spaghetti code! I probably won't clean it up since this is just a temporary implementation for testing purposes.
//!
//! It's also not a very good example because it doesn't properly utilize the websocket connection.

use std::collections::HashMap;
use std::time::Duration;

use actix_web_actors::ws::Frame;
use anyhow::Result;
use awc::{ws, Client};
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use bytestring::ByteString;
use futures_util::{SinkExt, StreamExt};
use omnisette::adi_proxy::{Identifier, AKD_USER_AGENT, CLIENT_INFO_HEADER, IDENTIFIER_LENGTH};
use plist::{Dictionary, Value};
use rand::RngCore;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    ClientBuilder, Response,
};
use sha2::Digest;
use sha2::Sha256;
use uuid::Uuid;

use crate::{provisioning_session, HeadersInput};

#[async_trait::async_trait]
trait ToPlist {
    async fn plist(self) -> Result<Dictionary>;
}

#[async_trait::async_trait]
impl ToPlist for Response {
    async fn plist(self) -> Result<Dictionary> {
        if let Ok(property_list) = Value::from_reader_xml(&*self.bytes().await?) {
            Ok(property_list.as_dictionary().unwrap().to_owned())
        } else {
            Err(anyhow::anyhow!("oh no"))
        }
    }
}

#[actix_web::test]
async fn test() -> Result<()> {
    // MARK: - Initial websocket connection

    let (_, mut ws) = Client::new()
        .ws("ws://0.0.0.0:8080/v3/provisioning_session")
        .connect()
        .await
        .unwrap();
    println!("connected");

    let next = match ws.next().await.unwrap().unwrap() {
        Frame::Text(t) => unsafe { ByteString::from_bytes_unchecked(t) }.to_string(),
        d => panic!("got unknown data: {d:?}"),
    };
    println!("got next: {next}");
    assert!(next.contains("Wait"));

    let next = match ws.next().await.unwrap().unwrap() {
        Frame::Text(t) => unsafe { ByteString::from_bytes_unchecked(t) }.to_string(),
        d => panic!("got unknown data: {d:?}"),
    };
    println!("got next: {next}");
    assert!(next.contains("GiveIdentifier"));

    // MARK: - Send identifier to server

    // let identifier_file_path = current_dir().unwrap().join("identifier");
    // let mut identifier_file = std::fs::OpenOptions::new()
    //     .create(true)
    //     .read(true)
    //     .write(true)
    //     .open(identifier_file_path)
    //     .unwrap();
    let mut identifier: Identifier = [0u8; IDENTIFIER_LENGTH];
    // if identifier_file.metadata().unwrap().len() == IDENTIFIER_LENGTH as u64 {
    //     identifier_file.read_exact(&mut identifier).unwrap();
    // } else {
    rand::thread_rng().fill_bytes(&mut identifier);
    // identifier_file.write_all(&identifier).unwrap();
    // }

    // let identifier = include_bytes!("../identifier");
    let identifier_base64 = base64_engine.encode(identifier);
    let input = serde_json::to_string(&provisioning_session::Identifier {
        identifier: identifier_base64.clone(),
    })
    .unwrap();
    println!("sending: {input}");
    ws.send(ws::Message::Text(input.into())).await.unwrap();
    std::thread::sleep(Duration::from_millis(250));

    let next = match ws.next().await.unwrap().unwrap() {
        Frame::Text(t) => unsafe { ByteString::from_bytes_unchecked(t) }.to_string(),
        d => panic!("got unknown data: {d:?}"),
    };
    println!("got next: {next}");
    assert!(next.contains("GiveStartProvisioningData"));

    // MARK: - HTTP client creation

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_str("text/x-xml-plist")?);

    let mut local_user_uuid_hasher = Sha256::new();
    local_user_uuid_hasher.update(identifier);

    headers.insert(
        "X-Mme-Client-Info",
        HeaderValue::from_str(CLIENT_INFO_HEADER)?,
    );
    headers.insert(
        "X-Mme-Device-Id",
        HeaderValue::from_str(
            Uuid::from_bytes(identifier.to_owned())
                .to_string()
                .to_uppercase()
                .as_str(),
        )?,
    );
    headers.insert(
        "X-Apple-I-MD-LU",
        HeaderValue::from_str(
            hex::encode(local_user_uuid_hasher.finalize())
                .to_uppercase()
                .as_str(),
        )?,
    );
    headers.insert("X-Apple-I-SRL-NO", HeaderValue::from_str("0")?);

    let client = ClientBuilder::new()
        .http1_title_case_headers()
        .danger_accept_invalid_certs(true) // TODO: pin the apple certificate
        .user_agent(AKD_USER_AGENT)
        .default_headers(headers)
        .build()?;

    // MARK: - Lookup urls

    let url_bag_res = client
        .get("https://gsa.apple.com/grandslam/GsService2/lookup")
        .send()
        .await?
        .plist()
        .await?;

    let urls = url_bag_res.get("urls").unwrap().as_dictionary().unwrap();

    let start_provisioning_url = urls
        .get("midStartProvisioning")
        .unwrap()
        .as_string()
        .unwrap();
    let finish_provisioning_url = urls
        .get("midFinishProvisioning")
        .unwrap()
        .as_string()
        .unwrap();

    // MARK: - Start provisioning request and send spim to server

    // Create a basically empty plist, containing the keys "Header" and "Request"
    let mut body = Dictionary::new();
    body.insert("Header".to_string(), Value::Dictionary(Dictionary::new()));
    body.insert("Request".to_string(), Value::Dictionary(Dictionary::new()));

    let mut sp_request = Vec::new();
    Value::Dictionary(body).to_writer_xml(&mut sp_request)?;

    let response = client
        .post(start_provisioning_url)
        .body(sp_request)
        .send()
        .await?
        .plist()
        .await?;

    let response = response.get("Response").unwrap().as_dictionary().unwrap();

    let spim = response
        .get("spim")
        .unwrap()
        .as_string()
        .unwrap()
        .to_owned();

    let input =
        serde_json::to_string(&provisioning_session::StartProvisioningData { spim }).unwrap();
    println!("sending: {input}");
    ws.send(ws::Message::Text(input.into())).await.unwrap();
    std::thread::sleep(Duration::from_millis(250));

    let next = match ws.next().await.unwrap().unwrap() {
        Frame::Text(t) => unsafe { ByteString::from_bytes_unchecked(t) }.to_string(),
        d => panic!("got unknown data: {d:?}"),
    };
    println!("got next: {next}");
    assert!(next.contains("GiveEndProvisioningData"));

    // MARK: - End provisioning request and send ptm and tk to server

    let data: HashMap<String, serde_json::Value> = serde_json::from_str(next.as_str()).unwrap();
    let cpim = data.get("cpim").unwrap().as_str().unwrap().to_string();

    let mut body = Dictionary::new();
    let mut request = Dictionary::new();
    request.insert("cpim".to_owned(), Value::String(cpim));
    body.insert("Header".to_owned(), Value::Dictionary(Dictionary::new()));
    body.insert("Request".to_owned(), Value::Dictionary(request));

    let mut fp_request = Vec::new();
    Value::Dictionary(body).to_writer_xml(&mut fp_request)?;

    let response = client
        .post(finish_provisioning_url)
        .body(fp_request)
        .send()
        .await?
        .plist()
        .await?;

    let response = response.get("Response").unwrap().as_dictionary().unwrap();

    let ptm = response
        .get("ptm")
        .unwrap()
        .as_string()
        .unwrap()
        .to_string();
    let tk = response.get("tk").unwrap().as_string().unwrap().to_string();

    let input =
        serde_json::to_string(&provisioning_session::EndProvisioningData { ptm, tk }).unwrap();
    println!("sending: {input}");
    ws.send(ws::Message::Text(input.into())).await.unwrap();
    std::thread::sleep(Duration::from_millis(250));

    let next = match ws.next().await.unwrap().unwrap() {
        Frame::Text(t) => unsafe { ByteString::from_bytes_unchecked(t) }.to_string(),
        d => panic!("got unknown data: {d:?}"),
    };
    println!("got next: {next}");
    assert!(next.contains("ProvisioningSuccess"));

    // MARK: - Get headers with received adi.pb

    let data: HashMap<String, serde_json::Value> = serde_json::from_str(next.as_str()).unwrap();
    let adi_pb = data.get("adi_pb").unwrap().as_str().unwrap().to_string();

    let response = client
        .post("http://0.0.0.0:8080/v3/get_headers")
        .body(
            serde_json::to_string(&HeadersInput {
                identifier: identifier_base64,
                adi_pb,
            })
            .unwrap(),
        )
        .header("Content-Type", "application/json")
        .send()
        .await?
        .text()
        .await?;
    println!("Headers response: {response}");

    Ok(())
}
