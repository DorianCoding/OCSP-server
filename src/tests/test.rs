use crate::rocket;
use crate::{Cli, Fileconfig, getprivatekey};
use clap::Parser;
use config_file::FromConfigFile;
use ring::{rand, signature};
use std::{fs, path::Path};
use zeroize::Zeroize;
#[test]
fn testresponse() {
    use ring::rand::SecureRandom;
    use ring::signature::KeyPair;
    use std::time::Instant;
    println!("Generating key, may take a while...");
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    // Normally the application would store the PKCS#8 file persistently. Later
    // it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

    println!("Done.");
    let mut tosign = [0u8; 3000];
    println!("Generating random");
    rng.fill(&mut tosign).unwrap();
    println!("Done!");
    let time = Instant::now();
    for i in 0..100 {
        if i % 10 == 0 {
            rng.fill(&mut tosign).unwrap();
        }
        let sig = key_pair.sign(&tosign);
        // Normally an application would extract the bytes of the signature and
        // send them in a protocol message to the peer(s). Here we just get the
        // public key key directly from the key pair.
        let peer_public_key_bytes = key_pair.public_key().as_ref();

        // Verify the signature of the message using the public key. Normally the
        // verifier of the message would parse the inputs to this code out of the
        // protocol message(s) sent by the signer.
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
        peer_public_key.verify(&tosign, sig.as_ref()).unwrap();
    }
    println!("Elapsed time : {:.6} ms", time.elapsed().as_millis());
}
#[test]
#[should_panic(
    expected = "called `Result::unwrap()` on an `Err` value: KeyRejected(\"InvalidEncoding\")"
)]
fn checkconfigfake() {
    let cli = Cli::parse();

    let config_path = &cli.config_path;

    if !Path::new(config_path).exists() {
        panic!("Config file not found at: {}", config_path);
    }

    let mut config = match Fileconfig::from_config_file(config_path) {
        Ok(config) => config,
        Err(e) => {
            panic!("Error reading config file at {}: {}", config_path, e);
        }
    };
    config.itkey = String::from("test_files/key.pem");
    //For an unknown reason, subject key identifier is not equal to SHA1 hash key so it is used instead.
    //let issuer_name_hash = certpem.subject_name_hash();
    let mut key = fs::read(&config.itkey).unwrap();
    let _rsakey = getprivatekey(&key).unwrap();
    key.zeroize();
}
#[test]
fn checkconfig() {
    rocket();
}
