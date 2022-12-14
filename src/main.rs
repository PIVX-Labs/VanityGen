use std::{
    process::exit,
    sync::mpsc,
    thread,
    thread::available_parallelism,
    time
};

use secp256k1::{Secp256k1, PublicKey, rand, SecretKey};
use ripemd::{Ripemd160, Digest};
use base58::ToBase58;
use bitcoin_hashes::{sha256d, sha256, Hash};
use clap::{Parser, command, arg};

pub struct OptimisedKeypair {
    private: SecretKey,
    public: String
}

pub struct VanityResult {
    keypair: OptimisedKeypair,
    iterations: u64
}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// VanityGen Target: the desired prefix to use for the address
   #[arg(long, default_value_t = String::default())]
   target: String,

   /// Number of threads to be used default is 1
   #[arg(long, default_value_t = 0)]
   threads: usize,
    /// VanityGen Case Insensitivity: can be set to reduce the generation time via wider Base58 scope
   #[arg(long, default_value_t = false)]
   case_insensitive: bool,
}

fn main() {

    let cli = Args::parse();
    // Settings and their defaults
    let mut threads = cli.threads;

    let mut target = cli.target;

    let case_insensitive = cli.case_insensitive;

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

        // Enforce and cache our target's capitalisation
        if case_insensitive {
            target = target.to_lowercase();
        }

        // Spin up our key-gen threads
        let (tx, rx) = mpsc::channel();
        for _ in 0..threads {
            let ctx = tx.clone();
            let ctarget = target.clone();
            thread::spawn(move|| {
                ctx.send(vanitygen_blocking(ctarget, case_insensitive)).unwrap();
            });
        }

        // Start our key search
        let search_start = time::Instant::now();
        loop {
            let result = rx.recv().unwrap();

            // Check if the prefix matches the target
            let elapsed_time = search_start.elapsed();
            println!("Found in {}s, avg speed of {} keys per-sec", elapsed_time.as_secs_f32(), ((result.iterations as f32 * threads as f32) / elapsed_time.as_secs_f32()));
            dump_keypair(result.keypair);
            exit(0);
        }
    }
}

pub fn vanitygen_blocking(target: String, case_insensitive: bool) -> VanityResult {
    // Precompute a Secp256k1 context
    let secp = Secp256k1::new();
    let mut iterations: u64 = 0;

    loop {
        // Generate a keypair
        let keypair = create_pivx_address(&secp);

        // Apply case sensitivity rules
        let address = match case_insensitive {
            true => keypair.public.to_lowercase(),
            false => keypair.public.clone()
        };

        // Check if the prefix matches the target
        if address[..target.len()] == target {
            return VanityResult{keypair, iterations}
        }
        iterations += 1;
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