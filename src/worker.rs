use crate::logger;
use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    x25519, Decryptor, Encryptor, Identity, Recipient,
};
use anyhow::{anyhow, Context, Error, Result};
use bastion::prelude::*;
use edn_rs::Edn;
use secrecy::{ExposeSecret, Secret};
use std::{
    collections::HashSet,
    fs,
    io::{copy, Read, Write},
    str::FromStr,
};

#[derive(Debug)]
struct LogseqMetadata {
    db_encrypted_secret: String,
    db_encrypted: bool,
}

pub(crate) mod msg {
    use std::path::PathBuf;
    #[derive(Debug)]
    pub(crate) struct Encrypt {
        pub path: PathBuf,
        pub password: String,
    }
    #[derive(Debug)]
    pub(crate) struct Decrypt {
        pub path: PathBuf,
        pub password: String,
    }
}

use msg::*;

pub(crate) async fn worker(ctx: BastionContext, logger: ChildrenRef) -> Result<(), ()> {
    tracing::debug!("worker created");

    loop {
        msg! { ctx.recv().await?,
            msg: Encrypt => {
                let logger_ref = logger.clone();
                logger.broadcast(logger::UiToggle::Disable)
                    .expect("unable to send message to worker");

                let task = blocking! {
                    encrypt(msg, &logger_ref)
                };
                match task.await.transpose() {
                    Ok(_) => (),
                    Err(e) => {
                        ui_info(&logger, format!("Encryption failed: {}", e.to_string()));
                    }
                }

                logger.broadcast(logger::UiToggle::Enable)
                    .expect("unable to send message to worker");
            };
            msg: Decrypt => {
                let logger_ref = logger.clone();
                logger.broadcast(logger::UiToggle::Disable)
                    .expect("unable to send message to worker");

                let task = blocking! {
                    decrypt(msg, &logger_ref)
                };
                match task.await.transpose() {
                    Ok(_) => (),
                    Err(e) => {
                        ui_info(&logger, format!("Decryption failed: {}", e.to_string()));
                    }
                }

                logger.broadcast(logger::UiToggle::Enable)
                    .expect("unable to send message to worker");
            };
            _: _ => ();
        }
    }
}

fn ui_info(logger: &ChildrenRef, log: String) {
    logger
        .broadcast(logger::PutLogRequest(log))
        .expect("unable to send message to worker");
}

fn encrypt(msg: Encrypt, logger: &ChildrenRef) -> Result<()> {
    let metadata_path = msg.path;
    let content = fs::read_to_string(&metadata_path).unwrap();
    let metadata_edn = Edn::from_str(&content).unwrap();
    let metadata = LogseqMetadata {
        db_encrypted: metadata_edn[":db/encrypted?"].to_bool().unwrap_or(false),
        db_encrypted_secret: metadata_edn[":db/encrypted-secret"]
            .to_string()
            .strip_prefix("\"")
            .unwrap_or("")
            .strip_suffix("\"")
            .unwrap_or("")
            .replace("\\n", "\n"),
    };
    if metadata.db_encrypted {
        ui_info(
            logger,
            "Graph is already encrypted, please decrypt it first".to_string(),
        );
        return Ok(());
    }

    ui_info(
        logger,
        "Update metadata.edn to enable encryption...".to_string(),
    );
    let secret = x25519::Identity::generate();
    let public = secret.to_public();
    let secret_pair = format!(
        "(\"{}\" \"{}\")",
        secret.to_string().expose_secret(),
        public.to_string()
    );
    let mut encrypted_secret = Vec::new();
    let encryptor = Encryptor::with_user_passphrase(Secret::new(msg.password));
    let armor = ArmoredWriter::wrap_output(&mut encrypted_secret, Format::AsciiArmor)?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(Error::msg)
        .context("failed to create encryptor")?;
    writer.write_all(secret_pair.as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;

    let metadata_content = format!(
        "{{:db/encrypted? true :db/encrypted-secret \"{}\"}}",
        std::str::from_utf8(&encrypted_secret)?.replace("\n", "\\n")
    );
    let mut writer = fs::File::create(&metadata_path)?;
    writer.write_all(metadata_content.as_bytes())?;
    writer.flush()?;

    let graph_dir = metadata_path.parent().unwrap().parent().unwrap();

    ui_info(
        logger,
        format!(
            "Searching items in graph directory: {}",
            graph_dir.to_string_lossy()
        ),
    );

    let mut files = HashSet::new();
    for entry in walkdir::WalkDir::new(graph_dir) {
        let entry = entry?;
        if entry.file_type().is_file()
            && (entry.path().extension().map_or(false, |ext| ext.eq("md"))
                || entry.path().extension().map_or(false, |ext| ext.eq("org")))
        {
            tracing::info!("Found file {}", entry.path().display());
            files.insert(entry.path().to_owned());
        }
    }
    ui_info(logger, format!("Found {} files to process", files.len()));

    for item in files.iter() {
        let bak = item.with_file_name(format!("{}.bak", item.to_string_lossy()));
        ui_info(
            logger,
            format!("Backing up file to {}", bak.to_string_lossy()),
        );
        fs::rename(item, &bak)?;

        ui_info(logger, format!("Encrypting {}", item.to_string_lossy()));
        let mut output = fs::File::create(&item)?;
        let armor = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)?;
        let recipients = vec![Box::new(public.clone()) as Box<dyn Recipient>];
        let encryptor = Encryptor::with_recipients(recipients);
        let mut writer = encryptor.wrap_output(armor).map_err(Error::msg)?;
        let mut reader = fs::File::open(&bak)?;
        copy(&mut reader, &mut writer)?;
        writer.finish().and_then(|armor| armor.finish())?;
    }

    ui_info(logger, "Done!".to_string());
    Ok(())
}

fn decrypt(msg: Decrypt, logger: &ChildrenRef) -> Result<()> {
    let metadata_path = msg.path;
    let content = fs::read_to_string(&metadata_path).unwrap();
    let metadata_edn = Edn::from_str(&content).unwrap();
    let metadata = LogseqMetadata {
        db_encrypted: metadata_edn[":db/encrypted?"].to_bool().unwrap_or(false),
        db_encrypted_secret: metadata_edn[":db/encrypted-secret"]
            .to_string()
            .strip_prefix("\"")
            .unwrap_or("")
            .strip_suffix("\"")
            .unwrap_or("")
            .replace("\\n", "\n"),
    };
    if !metadata.db_encrypted {
        ui_info(logger, "Graph is not encrypted".to_string());
        return Ok(());
    }

    ui_info(
        logger,
        "Found encrypted secret, recovering secret key...".to_string(),
    );

    // Recover secret key
    let armor = ArmoredReader::new(metadata.db_encrypted_secret.as_bytes());
    let decryptor = match Decryptor::new(armor)? {
        Decryptor::Passphrase(d) => d,
        _ => {
            ui_info(logger, "Decrypting secrets failed".to_string());
            return Ok(());
        }
    };
    let mut decrypted = String::new();
    let mut reader = decryptor.decrypt(&Secret::new(msg.password), None)?;
    reader.read_to_string(&mut decrypted)?;
    let key_pair = Edn::from_str(&decrypted)?;
    let secret = key_pair[0].to_string();
    let secret = secret
        .strip_prefix("\"")
        .unwrap()
        .strip_suffix("\"")
        .unwrap();
    let identity: x25519::Identity = secret.parse().map_err(|_| anyhow!("parse secret error"))?;
    ui_info(logger, "Secret key recovered!".to_string());
    let graph_dir = metadata_path.parent().unwrap().parent().unwrap();
    ui_info(
        logger,
        format!(
            "Searching encrypted items in graph directory: {}",
            graph_dir.to_string_lossy()
        ),
    );

    let mut files = HashSet::new();
    for entry in walkdir::WalkDir::new(graph_dir) {
        let entry = entry?;
        if entry.file_type().is_file()
            && !entry.path().extension().map_or(false, |ext| ext.eq("bak"))
        {
            tracing::info!("Examining file {}", entry.path().display());
            let mut file = fs::File::open(entry.path())?;
            let mut buf = [0u8; 256];
            file.read(&mut buf)?;
            if buf.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
                || buf.starts_with(b"age-encryption.org/v1")
            {
                files.insert(entry.path().to_owned());
            }
        }
    }
    ui_info(logger, format!("Found {} files to process", files.len()));

    for item in files.iter() {
        let bak = item.with_file_name(format!("{}.bak", item.to_string_lossy()));
        ui_info(
            logger,
            format!("Backing up file to {}", bak.to_string_lossy()),
        );
        fs::rename(item, &bak)?;

        ui_info(logger, format!("Decrypting {}", item.to_string_lossy()));
        let armor = ArmoredReader::new(fs::File::open(&bak)?);
        let decryptor = match Decryptor::new(armor)? {
            Decryptor::Recipients(d) => d,
            _ => {
                ui_info(logger, "Decrypting failed, file skipped".to_string());
                continue;
            }
        };
        let identities = vec![Box::new(identity.clone()) as Box<dyn Identity>];
        let mut reader = decryptor.decrypt(identities.into_iter())?;
        let mut writer = fs::File::create(item)?;
        copy(&mut reader, &mut writer)?;
        writer.flush()?;
    }

    ui_info(
        logger,
        "Update metadata.edn to disable encryption...".to_string(),
    );
    let mut writer = fs::File::create(&metadata_path)?;
    writer.write_all(b"{:db/encrypted? false}")?;
    writer.flush()?;

    ui_info(logger, "Done!".to_string());
    Ok(())
}
