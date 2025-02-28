use std::sync::Arc;
use webauthn_rs::prelude::*;
use mongodb::{Client, Database};
use serde::{Serialize, Deserialize};
use dotenv::dotenv;
use tracing::info;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserData {
    pub username: String,
    #[serde(deserialize_with = "deserialize_uuid", serialize_with = "serialize_uuid")]
    pub unique_id: Uuid,
    pub passkeys: Vec<Passkey>,
}

fn deserialize_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    Uuid::parse_str(&s).map_err(serde::de::Error::custom)
}

fn serialize_uuid<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub db: Database,
}

impl AppState {
    pub async fn new() -> Self {
        dotenv().ok();

        let rp_id = "localhost";
        let rp_origin = Url::parse("http://localhost:3000").expect("Invalid URL");
        let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
        let builder = builder.rp_name("Axum Webauthn-rs");
        let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

        let mongo_uri = std::env::var("MONGODB_URI").expect("MONGODB_URI must be set in .env");
        info!("Connecting to MongoDB at URI: {}", mongo_uri);
        let client = Client::with_uri_str(&mongo_uri)
            .await
            .expect("Failed to connect to MongoDB");
        let db = client.database("polling-app");
        info!("Using database: webauthn_db, collection: users");

        Self { webauthn, db }
    }

    pub fn users_collection(&self) -> mongodb::Collection<UserData> {
        self.db.collection("users")
    }
}