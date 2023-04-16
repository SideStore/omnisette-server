use std::collections::HashMap;
use std::env::current_dir;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use log::{debug, error};
use omnisette::adi_proxy::{
    ADIProxy, ADIProxyAnisetteProvider, Identifier, StartProvisioningData, DS_ID, IDENTIFIER_LENGTH,
};
use omnisette::anisette_headers_provider::AnisetteHeadersProvider;
use omnisette::store_services_core::StoreServicesCoreADIProxy;
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct ProviderInstance {
    provider: ADIProxyAnisetteProvider<StoreServicesCoreADIProxy<'static>>,
    path: PathBuf,
    should_cleanup: bool,
}

impl ProviderInstance {
    pub fn new(
        identifier: Option<Identifier>,
        adi_pb: Option<Vec<u8>>,
    ) -> Result<ProviderInstance> {
        debug!("Creating a new ProviderInstance");
        let cwd = current_dir()?;

        let (identifier, uuid, path, should_cleanup) = match identifier {
            Some(identifier) => {
                let uuid = Uuid::from_bytes(identifier);
                (
                    identifier,
                    uuid,
                    cwd.join("provisioning").join(uuid.to_string()),
                    true,
                )
            }
            None => {
                let identifier_file_path = cwd.join("identifier");
                let mut identifier_file = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(identifier_file_path)?;
                let mut identifier = [0u8; IDENTIFIER_LENGTH];
                if identifier_file.metadata()?.len() == IDENTIFIER_LENGTH as u64 {
                    identifier_file.read_exact(&mut identifier)?;
                } else {
                    rand::thread_rng().fill_bytes(&mut identifier);
                    identifier_file.write_all(&identifier)?;
                }
                (identifier, Uuid::from_bytes(identifier), cwd.clone(), false)
            }
        };
        if std::fs::create_dir_all(&path).is_ok() {}

        if let Some(adi_pb) = adi_pb {
            let adi_pb_path = path.join("adi.pb");
            if let Err(e) = std::fs::write(&adi_pb_path, adi_pb) {
                error!("Got error writing adi.pb (writing to {adi_pb_path:?}): {e:?}");
                return Err(anyhow!("Couldn't write adi.pb. We don't give you the exact error message to ensure nothing sensitive is shown, so please contact the server owner with the exact time this happened!"));
            }
        }

        let mut adi_proxy = StoreServicesCoreADIProxy::with_custom_provisioning_path(&cwd, &path)?;

        adi_proxy.set_device_identifier(uuid.to_string().to_uppercase())?; // UUID, uppercase

        let mut local_user_uuid_hasher = Sha256::new();
        local_user_uuid_hasher.update(identifier);
        adi_proxy
            .set_local_user_uuid(hex::encode(local_user_uuid_hasher.finalize()).to_uppercase()); // 64 uppercase character hex

        debug!("Successfully created a ProviderInstance");
        Ok(ProviderInstance {
            provider: ADIProxyAnisetteProvider::without_identifier(adi_proxy).unwrap(), // this will never fail
            path,
            should_cleanup,
        })
    }

    pub async fn get_authentication_headers_v1(&mut self) -> Result<HashMap<String, String>> {
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

    pub async fn get_authentication_headers_v3(&mut self) -> Result<HashMap<String, String>> {
        let headers = self.provider.get_anisette_headers(true).await?;

        let mut headers = self.provider.normalize_headers(headers);

        headers.remove("X-Mme-Client-Info"); // SideStore will get this using /client_info endpoint

        // SideStore will provide these properties
        // Even if it gets a wrong device ID and MD LU for the identifier (which it shouldn't, I've tested it a lot and it always gave the same as Rust)
        // we want it to use the same thing as what it used to send requests to apple servers
        headers.remove("X-Mme-Device-Id");
        headers.remove("X-Apple-I-MD-LU");
        headers.remove("X-Apple-I-SRL-NO");

        Ok(headers)
    }

    pub fn start_provisioning(&mut self, spim: &[u8]) -> Result<StartProvisioningData> {
        self.provider
            .adi_proxy()
            .start_provisioning(DS_ID, spim)
            .map_err(|e| anyhow!(e))
    }

    pub fn end_provisioning(&mut self, session: u32, ptm: &[u8], tk: &[u8]) -> Result<Vec<u8>> {
        self.provider
            .adi_proxy()
            .end_provisioning(session, ptm, tk)
            .map_err(|e| anyhow!(e))?;

        let adi_pb_path = self.path.join("adi.pb");
        match std::fs::read(adi_pb_path) {
            Ok(d) => Ok(d),
            Err(e) => {
                error!("Got error reading adi.pb: {e:?}");
                Err(anyhow!("Couldn't read adi.pb. We don't give you the exact error message to ensure nothing sensitive is shown, so please contact the server owner with the exact time this happened!"))
            }
        }
    }

    pub fn destroy_provisioning_session(&mut self, session: u32) -> Result<()> {
        self.provider
            .adi_proxy()
            .destroy_provisioning_session(session)
            .map_err(|e| anyhow!(e))
    }
}

impl Drop for ProviderInstance {
    fn drop(&mut self) {
        if self.should_cleanup {
            match std::fs::remove_dir_all(&self.path) {
                Ok(_) => debug!("Successfully cleaned up {:?}", self.path),
                Err(e)=> error!("Got error removing folder, server hoster might have to manually cleanup (removing {:?}): {e:?}", self.path),
            };
        } else {
            debug!("Skipping cleanup for {:?}", self.path);
        }
    }
}
