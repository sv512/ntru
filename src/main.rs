use std::path::PathBuf;

use ntru::{
    encparams::DEFAULT_PARAMS_256_BITS,
    rand::{RandContext, RNG_DEFAULT},
    types::{KeyPair, PrivateKey, PublicKey},
};
use structopt::StructOpt;

/// Options accepted by the CLI
#[derive(StructOpt)]
#[structopt(author, about)]
enum Opt {
    /// Generate key pair
    Gen {
        /// Generate public key using private key file (optional)
        private_key: Option<PathBuf>,
    },

    /// Encrypt data using the public key
    Enc {
        /// File to encrypt
        #[structopt(parse(from_os_str))]
        file: PathBuf,

        /// Public key file in base64
        public_key: PathBuf,
    },

    /// Decrypt data using the private & public key
    Dec {
        /// File to decrypt
        #[structopt(parse(from_os_str))]
        file: PathBuf,

        /// Private key file in base64
        private_key: PathBuf,

        /// Public key file that the ciphertext has been encrypted with in
        /// base64
        public_key: PathBuf,
    },

    /// Print general information about the NTRU used here
    Info,
}

/// Get default RNG
fn get_rng() -> RandContext {
    ntru::rand::init(&RNG_DEFAULT).expect("failed to initialize rng")
}

/// Extract public key from file containing base64 string
fn read_public_key(maybe_key: PathBuf) -> PublicKey {
    let maybe_key = std::fs::read_to_string(maybe_key)
        .expect("can't read private key file");

    // Remove whitespaces from key and decode base64
    let public_key =
        base64::decode(maybe_key.trim()).expect("invalid public key");

    // Validate key size
    if public_key.len() != DEFAULT_PARAMS_256_BITS.public_len() as usize {
        panic!("invalid public key size");
    }

    PublicKey::import(&public_key)
}

/// Extract private key from file containing base64 string
fn read_private_key(maybe_key: PathBuf) -> PrivateKey {
    let maybe_key = std::fs::read_to_string(maybe_key)
        .expect("can't read private key file");

    // Remove whitespaces from key and decode base64
    let private_key =
        base64::decode(maybe_key.trim()).expect("invalid private key");

    // Validate key size
    if private_key.len() != DEFAULT_PARAMS_256_BITS.private_len() as usize {
        panic!("invalid private key size");
    }

    PrivateKey::import(&private_key)
}

/// Print a public key generated using a private key and default parameters
fn generate_key_pair_from_private_key(private_key: PathBuf) {
    let private_key = read_private_key(private_key);

    // Generate public key from private key using default parameters
    let public_key = ntru::generate_public(
        &DEFAULT_PARAMS_256_BITS,
        &private_key,
        &get_rng(),
    )
    .expect("failed to generate public key");

    // Convert to raw bytes
    let public_key = public_key.export(&DEFAULT_PARAMS_256_BITS);

    // Print the public key in base64
    println!("----------------- Public Key ------------------");
    println!("{}", base64::encode(public_key));
}

/// Print a private and public key pair generated using default parameters
fn generate_key_pair() {
    // Generate keys using default parameters
    let key_pair =
        ntru::generate_key_pair(&DEFAULT_PARAMS_256_BITS, &get_rng())
            .expect("failed to generate key pair");

    // Convert to raw bytes
    let public_key = key_pair.get_public().export(&DEFAULT_PARAMS_256_BITS);
    let private_key = key_pair.get_private().export(&DEFAULT_PARAMS_256_BITS);

    // Print the keys in base64

    println!("----------------- Public Key ------------------");
    println!("{}", base64::encode(public_key));

    println!();

    println!("----------------- Private Key -----------------");
    println!("{}", base64::encode(private_key));
}

/// Encrypt a plaintext file
fn encrypt(file: PathBuf, public_key: PathBuf) {
    let public_key = read_public_key(public_key);

    // Read plaintext
    let plaintext = std::fs::read(&file).expect("can't read file");

    // Encrypt: plaintext -> ciphertext
    let ciphertext = ntru::encrypt(
        &plaintext,
        &public_key,
        &DEFAULT_PARAMS_256_BITS,
        &get_rng(),
    )
    .expect("failed to encrypt");

    // Replace plaintext file's content with ciphertext
    std::fs::write(file, ciphertext).expect("failed to write into file");
}

/// Decrypt a ciphertext file
fn decrypt(file: PathBuf, private_key: PathBuf, public_key: PathBuf) {
    let private_key = read_private_key(private_key);
    let public_key = read_public_key(public_key);

    let key_pair = KeyPair::new(private_key, public_key);

    // Read ciphertext
    let ciphertext = std::fs::read(&file).expect("can't read file");

    // Decrypt: ciphertext -> plaintext
    let plaintext =
        ntru::decrypt(&ciphertext, &key_pair, &DEFAULT_PARAMS_256_BITS)
            .expect("failed to decrypt");

    // Replace ciphertext file's content with plaintext
    std::fs::write(file, plaintext).expect("failed to write into file");
}

/// Print general information
fn print_general_information() {
    let x = DEFAULT_PARAMS_256_BITS;
    let backend = "libntru (https://github.com/tbuktu/libntru)";

    // Should always be 3
    let p = 3;

    println!("     parameter set name :: {}", x.get_name());
    println!("    ntruencrypt backend :: {}", backend);
    println!("      public key length :: {}", x.public_len());
    println!("     private key length :: {}", x.private_len());
    println!("      ciphertext length :: {}", x.enc_len());
    println!("   max plaintext length :: {}", x.max_msg_len());
    println!("random left bit padding :: {}", x.get_db());
    println!("polynomial coefficients :: {} = N", x.get_n());
    println!("        smaller modulus :: {}    = p", p);
    println!("         larger modulus :: {} = q", x.get_q());
}

fn main() {
    let opt = Opt::from_args();

    // Execute the correct function depending on the arguments
    match opt {
        Opt::Gen { private_key } => match private_key {
            None => generate_key_pair(),
            Some(private_key) => {
                generate_key_pair_from_private_key(private_key)
            },
        },
        Opt::Enc { file, public_key } => encrypt(file, public_key),
        Opt::Dec {
            file,
            private_key,
            public_key,
        } => decrypt(file, private_key, public_key),
        Opt::Info => print_general_information(),
    }
}
