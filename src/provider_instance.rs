use std::collections::HashMap;
use std::env::current_dir;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use omnisette::adi_proxy::{
    ADIProxy, ADIProxyAnisetteProvider, ConfigurableADIProxy, Identifier, StartProvisioningData,
    DS_ID, IDENTIFIER_LENGTH,
};
use omnisette::anisette_headers_provider::AnisetteHeadersProvider;
use omnisette::store_services_core::StoreServicesCoreADIProxy;
use parking_lot::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub type WrappedProvider = actix_web::web::Data<Mutex<ProviderInstance>>;

pub fn get_path_and_uuid_for_identifier(identifier: Identifier) -> (PathBuf, Uuid) {
    let uuid = Uuid::from_bytes(identifier);
    let mut path = current_dir().unwrap();
    path.push("provisioning");
    path.push(uuid.to_string());
    (path, uuid)
}

pub struct ProviderInstance {
    provider: ADIProxyAnisetteProvider<StoreServicesCoreADIProxy<'static>>,
    original_identifier: Identifier,
    current_identifier: Identifier,
    original_path: PathBuf,
    current_path: PathBuf,
    pub busy: bool,
}

impl ProviderInstance {
    pub fn new() -> ProviderInstance {
        info!("Initializing a ProviderInstance");

        let current_directory = current_dir().unwrap();

        let mut adi_proxy = StoreServicesCoreADIProxy::new(&current_directory).unwrap();
        adi_proxy
            .set_provisioning_path(current_directory.to_str().unwrap())
            .unwrap();

        let identifier_file_path = current_directory.join("identifier");
        let mut identifier_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(identifier_file_path)
            .unwrap();
        let mut identifier = [0u8; IDENTIFIER_LENGTH];
        if identifier_file.metadata().unwrap().len() == IDENTIFIER_LENGTH as u64 {
            identifier_file.read_exact(&mut identifier).unwrap();
        } else {
            rand::thread_rng().fill_bytes(&mut identifier);
            identifier_file.write_all(&identifier).unwrap();
        }

        let mut instance = ProviderInstance {
            provider: ADIProxyAnisetteProvider::without_identifier(adi_proxy).unwrap(),
            original_identifier: identifier,
            current_identifier: [0u8; IDENTIFIER_LENGTH],
            original_path: current_directory.clone(),
            current_path: current_directory,
            busy: false,
        };
        instance.set_identifier(identifier, None).unwrap();
        info!("Initialization complete");
        instance
    }

    pub fn adi_proxy(&mut self) -> &mut StoreServicesCoreADIProxy<'static> {
        self.provider.adi_proxy()
    }

    pub fn set_identifier(&mut self, identifier: Identifier, uuid: Option<Uuid>) -> Result<()> {
        if self.current_identifier == identifier {
            debug!("skipping set_identifier because identifier is equal to current_identifier");
            return Ok(());
        }

        let mut local_user_uuid_hasher = Sha256::new();
        local_user_uuid_hasher.update(identifier);

        let uuid = match uuid {
            Some(u) => u,
            None => Uuid::from_bytes(identifier),
        };
        self.adi_proxy()
            .set_device_identifier(uuid.to_string().to_uppercase())?; // UUID, uppercase
        self.adi_proxy()
            .set_local_user_uuid(hex::encode(local_user_uuid_hasher.finalize()).to_uppercase()); // 64 uppercase character hex

        self.current_identifier = identifier;
        debug!("successfully changed identifier");

        Ok(())
    }

    pub fn set_path(&mut self, path: PathBuf) -> Result<()> {
        if self.current_path == path {
            debug!("skipping set_path because path is equal to current_path");
            return Ok(());
        }

        if std::fs::create_dir_all(&path).is_ok() {}
        self.adi_proxy()
            .set_provisioning_path(path.to_str().ok_or(anyhow::anyhow!("bad path"))?)?;
        self.current_path = path;
        debug!("successfully changed path");

        Ok(())
    }

    pub fn set_identifier_and_path(&mut self, identifier: Identifier) -> Result<PathBuf> {
        let (path, uuid) = get_path_and_uuid_for_identifier(identifier);
        self.set_identifier(identifier, Some(uuid))?;
        self.set_path(path.clone())?;
        Ok(path)
    }

    pub async fn get_authentication_headers(&mut self) -> Result<HashMap<String, String>> {
        self.set_identifier(self.original_identifier, None)?;
        self.set_path(self.original_path.clone())?;
        let mut headers = self.provider.get_anisette_headers(false).await?;

        // Provision servers give X-MMe-Client-Info because AltServer gives X-MMe-Client-Info.
        // However, it's actually incorrect, and omnisette will normalize it to be X-Mme-Client-Info when using provider.get_authentication_headers().
        // To maintain backwards compatibility with V1 (and older versions of SideStore), we clone the header to ensure it is in both the correct and incorrect header key.
        // We don't need to do this for V3 (`/get_headers`, get_authentication_headers_unique) because versions of SideStore that support V3 will use the correct header.
        if let Some(client_info) = headers.get("X-Mme-Client-Info") {
            headers.insert("X-MMe-Client-Info".to_string(), client_info.clone());
        } else if let Some(client_info) = headers.get("X-MMe-Client-Info") {
            headers.insert("X-Mme-Client-Info".to_string(), client_info.clone());
        }

        // omnisette doesn't provide X-Apple-I-Client-Time, X-Apple-I-TimeZone or X-Apple-Locale headers because the client should provide them
        // for V1 requests, we need to manually add them
        headers.insert(
            "X-Apple-I-Client-Time".to_string(),
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        headers.insert("X-Apple-I-TimeZone".to_string(), "UTC".to_string());
        headers.insert("X-Apple-Locale".to_string(), "en_US".to_string());

        Ok(headers)
    }

    pub async fn get_authentication_headers_unique(
        &mut self,
        identifier: Identifier,
        adi_pb: Vec<u8>,
    ) -> Result<HashMap<String, String>> {
        let folder = self.set_identifier_and_path(identifier)?;
        if let Err(e) = std::fs::create_dir_all(&folder) {
            error!("Got error creating folder (creating {folder:?}): {e:?}");
            // Don't report this to the user because it might not be a problem
        }
        let path = folder.join("adi.pb");
        // use match instead of ? to ensure we don't show anything sensitive
        if let Err(e) = std::fs::write(&path, adi_pb) {
            error!("Got error writing adi.pb (writing to {path:?}): {e:?}");
            return Err(anyhow!("Couldn't write adi.pb. We don't give you the exact error message to ensure nothing sensitive is shown, so please contact the server owner with the exact time this happened!"));
        }
        let headers = self.provider.get_anisette_headers(true).await?;
        if let Err(e) = std::fs::remove_dir_all(&folder) {
            error!("Got error removing folder, server hoster might have to manually cleanup (removing {folder:?}): {e:?}");
            // Don't report this to the user because it might not be a problem
        }
        let mut headers = self.provider.normalize_headers(headers);

        headers.remove("X-Mme-Client-Info"); // SideStore will get this using /client_info endpoint

        // SideStore will provide these properties
        // Even if it gets a wrong device ID and MD LU for the identifier (which it shouldn't, I've tested it a lot and it always gave the same as Rust)
        // we want to to use the same thing as what it used to send requests to apple servers
        headers.remove("X-Mme-Device-Id");
        headers.remove("X-Apple-I-MD-LU");
        headers.remove("X-Apple-I-SRL-NO");

        Ok(headers)
    }

    pub fn start_provisioning(
        &mut self,
        identifier: Identifier,
        spim: &[u8],
    ) -> Result<StartProvisioningData> {
        self.set_identifier(identifier, None)?;
        let res = self.adi_proxy().start_provisioning(DS_ID, spim);
        match res {
            Ok(r) => Ok(r),
            Err(e) => Err(anyhow!(e)),
        }
    }

    pub fn end_provisioning(
        &mut self,
        identifier: Identifier,
        session: u32,
        ptm: &[u8],
        tk: &[u8],
    ) -> Result<PathBuf> {
        let path = self.set_identifier_and_path(identifier)?;
        let res = self.adi_proxy().end_provisioning(session, ptm, tk);
        match res {
            Ok(_) => Ok(path),
            Err(e) => Err(anyhow!(e)),
        }
    }
}
