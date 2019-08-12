use std::collections::HashSet;
use std::convert::From;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{self, Stdio};

use base64;
use clap::{App, Arg, ArgMatches, SubCommand};
use dialoguer::{Input, PasswordInput};
use dirs::home_dir;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{pwhash::scryptsalsa208sha256, secretbox};

const RTAHIN_DIRECTORY: &str = ".rtahin";
const RTAHIN_MPC_FILE: &str = "mpc";
const RTAHIN_MPC_DESCRIPTION_FILE: &str = "desc";
const PASSWORD_HANDLER_ENV_NAME: &str = "RTAHIN_PASSWORD_HANDLER";

#[derive(Debug, Clone, PartialEq, Eq)]
enum TahinError {
    ContainerNotFound,
    ContainerDescriptionNotFound,
    ContainerLoadFailure(String),
    IO(String),
    PasswordHandlerFailure(process::ExitStatus),
    CryptoFailure(String),
}

impl Display for TahinError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        use TahinError::*;
        match *self {
            TahinError::IO(ref msg) => f.write_str(&format!("IO Error: {}", msg)),
            ContainerNotFound => f.write_str("Container not found"),
            ContainerDescriptionNotFound => f.write_str("Container description not found"),
            ContainerLoadFailure(ref msg) => {
                f.write_str(&format!("Failed to load container: {}", msg))
            }
            PasswordHandlerFailure(exit_code) => f.write_str(&format!(
                "Password Handler terminated with exit code {}",
                exit_code
            )),
            CryptoFailure(ref msg) => f.write_str(&format!("CryptoFailure: {}", msg)),
        }
    }
}

impl From<io::Error> for TahinError {
    fn from(err: io::Error) -> TahinError {
        TahinError::IO(err.to_string())
    }
}

impl From<serde_json::Error> for TahinError {
    fn from(err: serde_json::Error) -> TahinError {
        TahinError::ContainerLoadFailure(format!("JSON Deserialization Failure: {}", err))
    }
}

impl From<base64::DecodeError> for TahinError {
    fn from(err: base64::DecodeError) -> TahinError {
        TahinError::ContainerLoadFailure(format!("Base64 Decoding Failure: {}", err))
    }
}

#[derive(Clone, Debug)]
struct MasterPassword(String);

impl MasterPassword {
    pub fn fingerprint(&self) -> MasterPasswordFingerprint {
        let mut hasher = Sha256::default();
        let data = b"FINGEPRINT|";
        hasher.input(data);
        hasher.input(&self.0);
        let result = hasher.result();
        MasterPasswordFingerprint(result.to_vec())
    }

    fn derive_password(&self, service: &Service) -> Password {
        let mut hasher = Sha256::default();
        hasher.input(&self.0);
        hasher.input(b" ");;
        hasher.input(&service.id.0);
        let hash_result = hasher.result();
        let b64_encoded_result: String = base64::encode(&hash_result);
        let password = &b64_encoded_result[0..20];
        Password(password.to_string())
    }

    fn from_user_new() -> Result<MasterPassword, TahinError> {
        loop {
            let p1 = PasswordInput::new()
                .with_prompt("Master Password")
                .interact()?;
            let p2 = PasswordInput::new()
                .with_prompt("Master Password (verification)")
                .interact()?;

            if p1 == p2 {
                return Ok(MasterPassword(p1));
            } else {
                println!("Mismatch, try again.");
                continue;
            }
        }
    }

    fn from_user() -> Result<MasterPassword, TahinError> {
        Ok(MasterPassword(
            PasswordInput::new()
                .with_prompt("Master Password")
                .interact()?,
        ))
    }

    fn from_user_cleartext() -> Result<MasterPassword, TahinError> {
        Ok(MasterPassword(
            Input::new().with_prompt("Master Password").interact()?,
        ))
    }
}

#[derive(Clone, Debug)]
struct Password(String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterPasswordFingerprint(Vec<u8>);

impl MasterPasswordFingerprint {
    pub fn mpc_base_path(&self) -> Result<PathBuf, TahinError> {
        let mut path = match home_dir() {
            Some(path) => path,
            None => Err(TahinError::IO("Home directory not found".to_string()))?,
        };
        path.push(RTAHIN_DIRECTORY);
        path.push(hex::encode(&self.0));
        Ok(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
struct ServiceId(String);

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
struct Service {
    id: ServiceId,
}

impl Service {
    pub fn query(mpc: &MasterPasswordContainer) -> Result<Service, TahinError> {
        use dialoguer::Confirmation;

        let service_id = Input::<String>::new().with_prompt("Service").interact()?;
        let service = Service {
            id: ServiceId(service_id),
        };

        if mpc.container.services.contains(&service) {
            // Found.
            Ok(service)
        } else {
            println!("Service '{}' currently unknown.", service);

            if Confirmation::new()
                .with_text("Do you want to continue?")
                .interact()?
            {
                Ok(service)
            } else {
                process::exit(0)
            }
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[derive(Debug, Clone)]
struct MasterPasswordContainer {
    fingerprint: MasterPasswordFingerprint,
    container: MasterPasswordContainerStripped,
    description: ContainerDescription,
    mp: MasterPassword,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MasterPasswordContainerStripped {
    services: HashSet<Service>,
}

trait RTahinSecretBox {
    fn encrypt(&self, m: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError>;
    fn decrypt(&self, c: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ContainerDescription {
    V1(SodiumoxideSecretBox),
}

impl ContainerDescription {
    pub fn new() -> Self {
        ContainerDescription::V1(SodiumoxideSecretBox::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SodiumoxideSecretBox {
    salt: scryptsalsa208sha256::Salt,
    nonce: secretbox::Nonce,
}

impl SodiumoxideSecretBox {
    fn derive_key(
        &self,
        mp: &MasterPassword,
    ) -> Result<secretbox::xsalsa20poly1305::Key, TahinError> {
        let password: &[u8] = mp.0.as_bytes();
        let mut derived_key: [u8; 32] = [0; 32];
        scryptsalsa208sha256::derive_key(
            &mut derived_key,
            password,
            &self.salt,
            scryptsalsa208sha256::OPSLIMIT_INTERACTIVE,
            scryptsalsa208sha256::MEMLIMIT_INTERACTIVE,
        )
        .map_err(|_| {
            TahinError::CryptoFailure("Failed to derive key for Sodiumoxide SecretBox".to_string())
        })?;
        secretbox::xsalsa20poly1305::Key::from_slice(&derived_key)
            .map(Ok)
            .unwrap_or_else(|| {
                Err(TahinError::CryptoFailure(
                    "Failed to create key from slice".to_string(),
                ))
            })
    }

    pub fn new() -> Self {
        let salt = scryptsalsa208sha256::gen_salt();
        let nonce = secretbox::gen_nonce();
        SodiumoxideSecretBox { salt, nonce }
    }
}

impl RTahinSecretBox for SodiumoxideSecretBox {
    fn encrypt(&self, m: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError> {
        let derived_key = self.derive_key(&k)?;
        let ciphertext = secretbox::seal(m, &self.nonce, &derived_key);
        Ok(ciphertext)
    }

    fn decrypt(&self, c: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError> {
        let derived_key = self.derive_key(&k)?;
        let plaintext = secretbox::open(c, &self.nonce, &derived_key)
            .map_err(|_| TahinError::IO("Ciphertext authentication failure".to_string()))?;
        Ok(plaintext)
    }
}

impl RTahinSecretBox for ContainerDescription {
    fn encrypt(&self, m: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError> {
        match self {
            ContainerDescription::V1(secret_box) => secret_box.encrypt(m, k),
        }
    }
    fn decrypt(&self, c: &[u8], k: &MasterPassword) -> Result<Vec<u8>, TahinError> {
        match self {
            ContainerDescription::V1(secret_box) => secret_box.decrypt(c, k),
        }
    }
}

impl MasterPasswordContainer {
    pub fn new(mp: MasterPassword) -> MasterPasswordContainer {
        let fingerprint = mp.fingerprint();
        let services = Default::default();
        let container = MasterPasswordContainerStripped { services };
        let description = ContainerDescription::new();
        MasterPasswordContainer {
            fingerprint,
            container,
            description,
            mp,
        }
    }

    fn persist_description(&self) -> Result<(), TahinError> {
        let mpcm = serde_json::to_string(&self.description)?;
        let base_path = self.fingerprint.mpc_base_path()?;
        let mpcs_file = {
            let mut path = base_path.clone();
            path.push(RTAHIN_MPC_DESCRIPTION_FILE);
            path.set_extension("json");
            path
        };
        fs::create_dir_all(&base_path)?;
        fs::write(mpcs_file, mpcm.as_bytes())?;
        Ok(())
    }

    fn persist_mpc(&self) -> Result<(), TahinError> {
        let mpc = serde_json::to_string(&self.container)?;
        let mpcs_file = {
            let mut path = self.fingerprint.mpc_base_path()?.clone();
            path.push(RTAHIN_MPC_FILE);
            path
        };
        let encrypted = self.description.encrypt(mpc.as_bytes(), &self.mp)?;
        let encrypted_b64 = base64::encode(&encrypted);
        fs::write(mpcs_file, &encrypted_b64)?;
        Ok(())
    }

    pub fn persist(&self) -> Result<(), TahinError> {
        self.persist_description()?;
        self.persist_mpc()?;
        Ok(())
    }

    fn load_description(mpc_base_path: &PathBuf) -> Result<ContainerDescription, TahinError> {
        let description_path = {
            let mut description_path = mpc_base_path.clone();
            description_path.push(RTAHIN_MPC_DESCRIPTION_FILE);
            description_path.set_extension("json");
            description_path
        };

        let content = match fs::read(description_path) {
            Ok(content) => content,
            Err(_err) => Err(TahinError::ContainerDescriptionNotFound)?,
        };

        let description: ContainerDescription = serde_json::from_slice(&content)?;

        Ok(description)
    }

    fn load_with_description(
        mpc_base_path: &PathBuf,
        description: &ContainerDescription,
        mp: &MasterPassword,
    ) -> Result<MasterPasswordContainer, TahinError> {
        let path = {
            let mut path = mpc_base_path.clone();
            path.push(RTAHIN_MPC_FILE);
            path
        };
        let ciphertext_b64 = match fs::read(path) {
            Ok(encrypted_content) => encrypted_content,
            Err(_err) => Err(TahinError::ContainerNotFound)?,
        };
        let ciphertext = base64::decode(&ciphertext_b64)?;
        let plaintext = description.decrypt(&ciphertext, mp)?;
        let fingerprint = mp.fingerprint();
        let container_stripped: MasterPasswordContainerStripped =
            serde_json::from_slice(&plaintext)?;
        let container = MasterPasswordContainer {
            fingerprint,
            container: container_stripped,
            description: description.clone(),
            mp: mp.clone(),
        };
        Ok(container)
    }

    pub fn load(mp: &MasterPassword) -> Result<MasterPasswordContainer, TahinError> {
        let mpf = mp.fingerprint();
        let path = mpf.mpc_base_path()?;
        if !path.as_path().exists() {
            Err(TahinError::ContainerNotFound)?;
        }
        let mpcm = Self::load_description(&path)?;
        let mpc = Self::load_with_description(&path, &mpcm, mp)?;
        Ok(mpc)
    }

    fn create_if_desired(mp: &MasterPassword) -> Result<MasterPasswordContainer, TahinError> {
        println!("This is a new master password.");
        if dialoguer::Confirmation::new()
            .with_text("Do you want to continue with new master password?")
            .interact()?
        {
            let mpc = MasterPasswordContainer::new(mp.clone());
            Ok(mpc)
        } else {
            process::exit(0)
        }
    }
}

struct PasswordHandler {
    command: String,
}

impl PasswordHandler {
    fn retrieve_from_env(var_name: &str) -> Result<Option<String>, TahinError> {
        use std::env;

        match env::var(var_name) {
            Ok(val) => Ok(Some(val)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err(TahinError::IO(
                "Handler environment variable not Unicode".to_string(),
            )),
        }
    }

    pub fn from_env() -> Result<Option<Self>, TahinError> {
        let opt_command = Self::retrieve_from_env(PASSWORD_HANDLER_ENV_NAME)?;
        Ok(opt_command.map(|command| PasswordHandler { command }))
    }

    pub fn send(&self, password: &Password) -> Result<(), TahinError> {
        use std::process::Command;

        let mut child = Command::new(self.command.clone())
            .stdin(Stdio::piped())
            .spawn()?;
        match child.stdin {
            Some(ref mut stdin) => stdin.write_all(&password.0.as_bytes())?,
            None => unimplemented!(),
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            Err(TahinError::PasswordHandlerFailure(output.status))?;
        }
        Ok(())
    }
}

fn default_workflow(top_args: &ArgMatches<'_>) -> Result<(), TahinError> {
    let opt_handler = PasswordHandler::from_env()?;
    let mp = if top_args.is_present(TopArguments::ShowPassword) {
        MasterPassword::from_user_cleartext()?
    } else {
        MasterPassword::from_user()?
    };
    let mut container = match MasterPasswordContainer::load(&mp) {
        Ok(container) => container,
        Err(err) => {
            use TahinError::*;
            match err {
                ContainerNotFound => MasterPasswordContainer::create_if_desired(&mp)?,
                _ => Err(err)?,
            }
        }
    };
    let service = Service::query(&container)?;
    container.container.services.insert(service.clone());
    container.persist()?;
    let password = mp.derive_password(&service);

    match opt_handler {
        Some(handler) => {
            handler.send(&password)?;
            println!("OK");
        }
        None => println!("{}", password.0),
    }

    Ok(())
}

enum TopArguments {
    ShowPassword,
}

impl AsRef<str> for TopArguments {
    fn as_ref(&self) -> &str {
        use TopArguments::*;
        match self {
            ShowPassword => &"show-password",
        }
    }
}

fn register_new_master_password(
    top_args: &ArgMatches<'_>,
    _args: &ArgMatches<'_>,
) -> Result<(), TahinError> {
    let mp = if top_args.is_present(TopArguments::ShowPassword) {
        MasterPassword::from_user_cleartext()?
    } else {
        MasterPassword::from_user_new()?
    };
    match MasterPasswordContainer::load(&mp) {
        Ok(_mpc) => {
            println!("Password already registered");
            process::exit(0);
        }
        Err(TahinError::ContainerNotFound) => {}
        Err(err) => {
            println!(
                "Error occured while checking for container existence: {}",
                err
            );
            process::exit(1);
        }
    }
    let mpc = MasterPasswordContainer::new(mp);
    mpc.persist()?;
    println!("OK");
    Ok(())
}

fn main() -> Result<(), TahinError> {
    let top_matches = App::new("RTahin")
        .version("1.0")
        .author("Moritz Clasmeier <mtesseract@silverratio.net>")
        .about("Generates Service Passwords")
        .arg(
            Arg::with_name(TopArguments::ShowPassword.as_ref())
                .long(TopArguments::ShowPassword.as_ref())
                .short("s")
                .help("Show passwords"),
        )
        .subcommand(SubCommand::with_name("register").about("Register new master Password"))
        .get_matches();
    if let Some(sub_matches) = top_matches.subcommand_matches("register") {
        register_new_master_password(&top_matches, sub_matches)
    } else {
        default_workflow(&top_matches)
    }
}
