use std::path::Path;
use ssh_key;
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey, KeypairData};
use rand::RngCore;
use ssh_key::{LineEnding, PrivateKey};

fn generate_pgp_auth_key() -> (String, PrivateKey) {
    // generate an ED25519 authentication key and return the private key and the ssh public key
    let mut rand: [u8; 32] = [0; 32];
    rand::thread_rng().fill_bytes(&mut rand);
    let pk = Ed25519PrivateKey::from_bytes(&rand);
    let kp = Ed25519Keypair::from(pk);
    let ssh_key = PrivateKey::new(KeypairData::Ed25519(kp), "hi").unwrap();
    let ssh_pub_key = ssh_key.public_key().to_openssh().unwrap();
    (ssh_pub_key, ssh_key)
}

fn main() {
    println!("Hello, world!");
    // find number of threads
    let num_cpus = num_cpus::get();
    // run on each thread
    let threads: Vec<_> = (0..num_cpus).map(|_| {
        std::thread::spawn(|| { find(); })
    }).collect();
    // wait for all threads to finish
    for t in threads {
        t.join().unwrap();
    }
}

fn find() {
    loop {
        let (pub_key, priv_key) = generate_pgp_auth_key();
        if pub_key.ends_with("PN hi") {
            println!("Hit on 2!");
            if pub_key.ends_with("GPN hi") {
                println!("# Hit on 3!");
                if pub_key.ends_with("GPN hi") {
                    println!("Found {pub_key}! Written to id_ed25519");
                    priv_key.write_openssh_file(Path::new("id_ed25519"), LineEnding::LF).unwrap();
                    std::process::exit(0);
                }
            }
        }
    }
}
