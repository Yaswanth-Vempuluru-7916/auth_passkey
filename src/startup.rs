use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use webauthn_rs::prelude::*;

pub struct Data {
    pub name_to_id: HashMap<String, Uuid>,
    pub keys: HashMap<Uuid, Vec<Passkey>>,
}

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub users: Arc<Mutex<Data>>,
}

impl AppState {
    pub fn new() -> Self {
        // Effective domain name (still "localhost" since it's the same domain)
        let rp_id = "localhost";
        // Update to the frontend's URL where WebAuthn is initiated
        let rp_origin = Url::parse("http://localhost:3000").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");

        let builder = builder.rp_name("Axum Webauthn-rs");
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

        let users = Arc::new(Mutex::new(Data {
            name_to_id: HashMap::new(),
            keys: HashMap::new(),
        }));

        AppState { webauthn, users }
    }
}