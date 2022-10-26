use std::{
    process::exit,
    sync::mpsc,
    thread,
    thread::available_parallelism,
    time,
    env
};

use secp256k1::{Secp256k1, PublicKey, rand, SecretKey};
use ripemd::{Ripemd160, Digest};
use base58::ToBase58;
use bitcoin_hashes::{sha256d, sha256, Hash};

pub struct OptimisedKeypair {
    private: SecretKey,
    public: String
}

fn main() {
    // Settings and their defaults
    let mut threads = 0;

    let mut target = String::from("D");

    let mut case_insensitive = false;

    // Init: Parse arguments and adjust settings accordingly
    for arg in env::args() {

        // VanityGen Target: the desired prefix to use for the address
        if arg.starts_with("--target=") {
            // User-set target prefix
            target = arg[9..].to_string();
        }

        // VanityGen Threads: only needed if a target prefix is selected
        if arg.starts_with("--threads=") && target.len() > 1 {
            // User-set count OR system available_paralellism
            threads = arg[10..].parse().unwrap_or(0);
        }

        // VanityGen Case Insensitivity: can be set to reduce the generation time via wider Base58 scope
        if arg == "--case-insensitive" {
            target = target.to_lowercase();
            case_insensitive = true;
        }

    }

    if target.len() == 1 {
        // Generate a single keypair and immediately return + exit
        let secp = Secp256k1::new();
        dump_keypair(create_pivx_address(&secp));
        exit(0);
    } else {
        // If no threading is selected, we auto-select all available threads, or bail out if not possible
        if threads <= 0 {
            threads = usize::from(available_parallelism().unwrap_or_else(|_| {
                eprintln!("Init Failure: thread count is invalid and the fallback thread estimator failed.");
                exit(1);
            }));
        }
        // Notify we're running multi-threaded
        println!("Running at {} threads", threads);

        // Spin up our key-gen threads
        let (tx, rx) = mpsc::channel();
        for _ in 0..threads {
            let ctx = tx.clone();
            thread::spawn(move|| {
                let secp = Secp256k1::new();
                loop {
                    ctx.send(create_pivx_address(&secp)).unwrap();
                }
            });
        }

        // Start our key search
        let search_start = time::Instant::now();
        let mut iterations: u64 = 0;
        loop {
            let received = rx.recv().unwrap();

            // Apply case sensitivity rules
            let address = match case_insensitive {
                true => received.public.to_lowercase(),
                false => received.public.clone()
            };

            // Check if the prefix matches the target
            if address[..target.len()] == target {
                let elapsed_time = search_start.elapsed();
                println!("Found in {}s, avg speed of {} keys per-sec", elapsed_time.as_secs_f32(), (iterations as f32 / elapsed_time.as_secs_f32()));
                dump_keypair(received);
                exit(0);
            }
            iterations += 1;
        }
    }
}

pub fn dump_keypair(keypair: OptimisedKeypair) {
    println!("Here's your PIVX address!\r\n - Address: {}\r\n - Private Key: {}", keypair.public, secret_to_wif(keypair.private));
}

pub fn secret_to_wif(privkey: SecretKey) -> String {
    // Convert into byte format
    let privkey_bytes = privkey.secret_bytes();

    // Format the byte payload into WIF format
    let mut wif_bytes = vec![212];
    wif_bytes.extend_from_slice(&privkey_bytes);
    wif_bytes.extend_from_slice(&[1]);

    // Concat the WIF bytes with it's SHA256d checksum.
    let sha256d_wif = sha256d::Hash::hash(&wif_bytes).into_inner();
    wif_bytes.extend_from_slice(&sha256d_wif[..4]);

    // Return the WIF String
    wif_bytes.to_base58()
}

pub fn pubkey_to_address(pubkey: PublicKey) -> String {
    // Convert into byte format
    let pubkey_bytes = pubkey.serialize();

    // First sha256 round of the compressed pubkey
    let pre_ripemd = sha256::Hash::hash(&pubkey_bytes).into_inner();

    // Then a ripemd160 round
    let mut ripemd_factory = Ripemd160::new();
    ripemd_factory.update(&pre_ripemd);
    let public_key_hash = ripemd_factory.finalize();

    // Create the double-SHA256 Checksum for the network public key hash
    let mut address_bytes = vec![30];
    address_bytes.extend_from_slice(&public_key_hash);
    let sha256d = sha256d::Hash::hash(&address_bytes).into_inner();

    // Concat the address bytes with it's checksum.
    address_bytes.extend_from_slice(&sha256d[..4]);

    // Return the Base58 address
    address_bytes.to_base58()
}

pub fn create_pivx_address(secp: &Secp256k1<secp256k1::All>) -> OptimisedKeypair {
    // Compute a new secret
    let privkey = SecretKey::new(&mut rand::thread_rng());

    // Derive a Secp256k1 Public Key from the secret using a cached secp context
    let pubkey = PublicKey::from_secret_key(&secp, &privkey);

    // Process the Secp256k1 Public Key into a Network Address
    let address = pubkey_to_address(pubkey);

    // Return the keypair without any private key post-processing
    OptimisedKeypair{private: privkey, public: address}
}