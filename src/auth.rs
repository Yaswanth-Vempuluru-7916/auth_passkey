use axum::{
    extract::{Extension, Json, Path},
    http::StatusCode,
    response::IntoResponse,
};
use tower_sessions::Session;
use webauthn_rs::prelude::*;
use mongodb::bson::doc;
use uuid::Uuid;
use crate::error::WebauthnError;
use crate::startup::{AppState, UserData};

pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start register for username: {}", username);

    let user_unique_id = Uuid::new_v4();

    if let Err(e) = session.remove_value("reg_state").await {
        error!("Failed to remove previous reg_state from session: {:?}", e);
    } else {
        info!("Cleared previous reg_state from session");
    }

    let exclude_credentials: Option<Vec<CredentialID>> = {
        let collection = app_state.users_collection();
        match collection.find_one(doc! { "username": &username }).await {
            Ok(Some(user)) => {
                info!("Found existing user {} with {} passkeys", username, user.passkeys.len());
                Some(user.passkeys.into_iter().map(|sk| sk.cred_id().clone()).collect())
            }
            Ok(None) => {
                info!("No existing user found for {}", username);
                None
            }
            Err(e) => {
                error!("Failed to query user {}: {:?}", username, e);
                return Err(WebauthnError::MongoDBError(e));
            }
        }
    };

    let res = match app_state.webauthn.start_passkey_registration(
        user_unique_id,
        &username,
        &username,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            if let Err(e) = session.insert("reg_state", (username.clone(), user_unique_id, reg_state)).await {
                error!("Failed to insert reg_state into session: {:?}", e);
                return Err(WebauthnError::InvalidSessionState(e));
            }
            info!("Registration challenge generated for {} (UUID: {})", username, user_unique_id);
            Json(ccr)
        }
        Err(e) => {
            error!("Failed to start passkey registration for {}: {:?}", username, e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (username, user_unique_id, reg_state): (String, Uuid, PasskeyRegistration) = session
        .get("reg_state")
        .await?
        .ok_or_else(|| {
            error!("No reg_state found in session for registration completion");
            WebauthnError::CorruptSession
        })?;

    if let Err(e) = session.remove_value("reg_state").await {
        error!("Failed to remove reg_state from session: {:?}", e);
    } else {
        info!("Cleared reg_state from session for {}", username);
    }

    let res = match app_state.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(sk) => {
            let collection = app_state.users_collection();
            let user_data = UserData {
                username: username.clone(),
                unique_id: user_unique_id,
                passkeys: vec![sk],
            };

            let update_doc = doc! { 
                "$setOnInsert": { "unique_id": user_unique_id.to_string() }, // Convert to string
                "$push": { "passkeys": mongodb::bson::to_bson(&user_data.passkeys[0])? } 
            };
            info!("Attempting to upsert user {} with update: {:?}", username, update_doc);

            match collection
                .update_one(
                    doc! { "username": &username },
                    update_doc,
                )
                .with_options(mongodb::options::UpdateOptions::builder().upsert(true).build())
                .await
            {
                Ok(result) => {
                    info!(
                        "MongoDB update result: matched={}, modified={}, upserted_id={:?}",
                        result.matched_count, result.modified_count, result.upserted_id
                    );
                    if result.upserted_id.is_some() {
                        info!("Inserted new user {} (UUID: {}) into MongoDB", username, user_unique_id);
                    } else if result.modified_count > 0 {
                        info!("Appended passkey to existing user {} in MongoDB", username);
                    } else {
                        warn!("No changes made to MongoDB for user {} - possible issue", username);
                    }
                    StatusCode::OK
                }
                Err(e) => {
                    error!("Failed to upsert user {} into MongoDB: {:?}", username, e);
                    return Err(WebauthnError::MongoDBError(e));
                }
            }
        }
        Err(e) => {
            error!("Failed to finish passkey registration for {}: {:?}", username, e);
            StatusCode::BAD_REQUEST
        }
    };
    info!("Registration completed successfully for {}", username);
    Ok(res)
}

pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("Start authentication for username: {}", username);

    if let Err(e) = session.remove_value("auth_state").await {
        error!("Failed to remove previous auth_state from session: {:?}", e);
    } else {
        info!("Cleared previous auth_state from session");
    }

    let collection = app_state.users_collection();
    let user_data = match collection.find_one(doc! { "username": &username }).await {
        Ok(Some(user)) => {
            info!("Found user {} with {} passkeys for authentication", username, user.passkeys.len());
            user
        }
        Ok(None) => {
            error!("No user found for {} during authentication", username);
            return Err(WebauthnError::UserNotFound);
        }
        Err(e) => {
            error!("Failed to query user {} for authentication: {:?}", username, e);
            return Err(WebauthnError::MongoDBError(e));
        }
    };

    let res = match app_state.webauthn.start_passkey_authentication(&user_data.passkeys) {
        Ok((rcr, auth_state)) => {
            if let Err(e) = session.insert("auth_state", (user_data.unique_id, auth_state)).await {
                error!("Failed to insert auth_state into session: {:?}", e);
                return Err(WebauthnError::InvalidSessionState(e));
            }
            info!("Authentication challenge generated for {} (UUID: {})", username, user_data.unique_id);
            Json(rcr)
        }
        Err(e) => {
            error!("Failed to start passkey authentication for {}: {:?}", username, e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

pub async fn finish_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    let (user_unique_id, auth_state): (Uuid, PasskeyAuthentication) = session
        .get("auth_state")
        .await?
        .ok_or_else(|| {
            error!("No auth_state found in session for authentication completion");
            WebauthnError::CorruptSession
        })?;

    if let Err(e) = session.remove_value("auth_state").await {
        error!("Failed to remove auth_state from session: {:?}", e);
    } else {
        info!("Cleared auth_state from session for UUID: {}", user_unique_id);
    }

    let res = match app_state.webauthn.finish_passkey_authentication(&auth, &auth_state) {
        Ok(auth_result) => {
            let collection = app_state.users_collection();
            let user = match collection.find_one(doc! { "unique_id": user_unique_id.to_string() }).await {
                Ok(Some(user)) => {
                    info!("Found user with UUID {} for authentication update", user_unique_id);
                    user
                }
                Ok(None) => {
                    error!("No user found with UUID {} during authentication update", user_unique_id);
                    return Err(WebauthnError::UserHasNoCredentials);
                }
                Err(e) => {
                    error!("Failed to query user with UUID {}: {:?}", user_unique_id, e);
                    return Err(WebauthnError::MongoDBError(e));
                }
            };

            let mut user_data = user;
            for sk in user_data.passkeys.iter_mut() {
                sk.update_credential(&auth_result);
            }

            match collection
                .update_one(
                    doc! { "unique_id": user_unique_id.to_string() },
                    doc! { "$set": { "passkeys": mongodb::bson::to_bson(&user_data.passkeys)? } },
                )
                .await
            {
                Ok(_) => {
                    info!("Updated passkeys for user with UUID {} in MongoDB", user_unique_id);
                    StatusCode::OK
                }
                Err(e) => {
                    error!("Failed to update passkeys for UUID {} in MongoDB: {:?}", user_unique_id, e);
                    return Err(WebauthnError::MongoDBError(e));
                }
            }
        }
        Err(e) => {
            error!("Failed to finish passkey authentication for UUID {}: {:?}", user_unique_id, e);
            StatusCode::BAD_REQUEST
        }
    };
    info!("Authentication completed successfully for UUID {}", user_unique_id);
    Ok(res)
}