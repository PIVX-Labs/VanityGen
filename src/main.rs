use std::{
    process::exit,
    sync::mpsc,
    thread,
    thread::available_parallelism,
    time
};

use secp256k1::{Secp256k1, PublicKey, rand, rand::Rng, SecretKey};
use ripemd::{Ripemd160, Digest};
use base58::ToBase58;
use bitcoin_hashes::{sha256d, sha256, Hash};
use clap::{Parser, command, arg};

/// A struct representing an optimized keypair.
///
/// This struct contains a private key of type `SecretKey` and a public key represented as a string.
///
pub struct OptimisedKeypair {
    private: SecretKey,
    public: String
}

/// A struct representing an optimized promotional keypair.
///
/// This struct contains a private key of type `SecretKey`, a public key represented as a string,
/// and a promotional code represented as a string.
///
pub struct OptimisedPromoKeypair {
    private: SecretKey,
    public: String,
    code: String
}

/// A struct representing the result of a vanity address generation.
///
/// This struct contains an optimized keypair and the number of iterations performed.
///
pub struct VanityResult {
    /// The generated keypair that matches the vanity target.
    keypair: OptimisedKeypair,
    /// The number of iterations performed.
    iterations: u64,
}

/// Iterations required for a PIVX Promo to be derived.
///
/// This constant is an array of `u64` values, representing the iterations required for a PIVX
/// promotional key to be derived. Currently, only one value is present in the array.
///
pub const PROMO_TARGETS: [u64; 1] = [
    12_500_000,
];

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// VanityGen Target: the desired prefix to use for the address
   #[arg(long, default_value_t = String::default())]
   target: String,

   /// Number of threads to allocate
   #[arg(long, default_value_t = 0)]
   threads: usize,

    /// VanityGen Case Insensitivity: can be set to reduce the generation time via wider Base58 scope
   #[arg(long, default_value_t = false)]
   case_insensitive: bool,

   /// PIVX Promos Count: the desired quantity of Promo codes
   #[arg(long, default_value_t = 0)]
   promo_count: u64,

   /// PIVX Promos Prefix: the desired prefix to use for the Promo code(s)
   #[arg(long, default_value_t = String::from("PIVX Labs"))]
   promo_prefix: String,
}

fn main() {
    let cli = Args::parse();

    // VanityGen Settings
    let mut threads = cli.threads;
    let mut target = cli.target;
    let case_insensitive = cli.case_insensitive;

    // PIVX Promos Settings
    let promo_count = cli.promo_count;
    let promo_prefix = cli.promo_prefix;

    if promo_count > 0 {
        let mut i: u64 = 0;
        while i < promo_count {
            let promo = create_promo_key(&promo_prefix);
            let wif = secret_to_wif(promo.private);
            println!("- Promo: '{}' - Address: {} - WIF: {wif}", promo.code, promo.public);
            i += 1;
        }
        exit(0);
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

/// Generates a PIVX keypair until a vanity address with a specific prefix is found.
///
/// This function generates keypairs in a blocked thread while checking if the generated
/// PIVX address matches the specified vanity target. It repeats this process until a matching
/// address is found, and then returns the resulting keypair along with the number of iterations
/// performed.
///
/// # Arguments
///
/// * `target` - The desired vanity prefix for the address.
/// * `case_insensitive` - Indicates whether the matching should be case-insensitive.
///
/// # Returns
///
/// A `VanityResult` struct containing the keypair that matches the vanity target and the number
/// of iterations performed.
///
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

/// Prints the PIVX address and corresponding private key of a given keypair.
///
/// # Arguments
///
/// * `keypair` - An `OptimisedKeypair` struct containing the public and private keys.
///
pub fn dump_keypair(keypair: OptimisedKeypair) {
    println!("Here's your PIVX address!\r\n - Address: {}\r\n - Private Key: {}", keypair.public, secret_to_wif(keypair.private));
}

/// Converts a secret key into Wallet Import Format (WIF).
///
/// # Arguments
///
/// * `privkey` - The secret key to be converted.
///
/// # Returns
///
/// The secret key in WIF format as a string.
///
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

/// Converts a public key into a PIVX address.
///
/// # Arguments
///
/// * `pubkey` - The public key to be converted.
///
/// # Returns
///
/// The PIVX address as a string.
///
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

/// Creates a PIVX keypair by generating a new secret key and deriving the corresponding public key.
///
/// This function takes a `Secp256k1` context as input and uses it to compute a new secret key. It then
/// derives the corresponding public key using the cached `secp` context. Finally, it processes the
/// public key into a PIVX network address and returns an `OptimisedKeypair` struct containing the
/// generated private and public keys.
///
/// # Arguments
///
/// * `secp` - A reference to a `Secp256k1` context.
///
/// # Returns
///
/// An `OptimisedKeypair` struct containing the generated private and public keys.
///
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

/// A string representing the set of characters for generating alphanumeric random values.
/// 
const MAP_ALPHANUMERIC: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Returns a vector of random bytes of the specified size.
///
/// # Arguments
///
/// * `n_size` - The number of random bytes to generate.
///
/// # Returns
///
/// A vector of random bytes.
///
pub fn get_safe_rand(n_size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random_values = vec![0; n_size];
    rng.fill(&mut random_values[..]);
    random_values
}

/// Returns a randomly generated alphanumeric string of the specified size.
///
/// # Arguments
///
/// * `n_size` - The desired length of the generated string.
///
/// # Returns
///
/// A randomly generated alphanumeric string.
///
pub fn get_alpha_numeric_rand(n_size: usize) -> String {
    let mut result = String::new();
    let rand_values = get_safe_rand(n_size);
    for byte in rand_values {
        let index = (byte % MAP_ALPHANUMERIC.len() as u8) as usize;
        result.push(MAP_ALPHANUMERIC.chars().nth(index).unwrap());
    }
    result
}

/// Creates a PIVX Promos keypair based on a given prefix.
///
/// # Arguments
///
/// * `prefix` - A reference to a String representing the prefix of the promotional code.
///
/// # Returns
///
/// An `OptimisedPromoKeypair` struct containing the generated private and public keys, along with the promo code.
///
pub fn create_promo_key(prefix: &String) -> OptimisedPromoKeypair {
    // Precompute a Secp256k1 context
    let secp = Secp256k1::new();

    // Select the latest Target
    let target = PROMO_TARGETS.last().unwrap();

    // Generate entropy and append it to the promo code
    let promo_code = prefix.to_owned() + "-" + &get_alpha_numeric_rand(5);

    // Convert the Promo Code to it's first SHA256 hash
    let mut promo_key = sha256::Hash::hash(promo_code.as_bytes()).into_inner();

    // Recursively hash until we hit the target (minus one, as promo_key hashes it once)
    let mut iterations: u64 = 1;
    while &iterations < target {
        promo_key = sha256::Hash::hash(&promo_key).into_inner();
        iterations += 1;
    }

    // Generate the final keys
    let private = SecretKey::from_slice(&promo_key).unwrap();
    let public = pubkey_to_address(PublicKey::from_secret_key(&secp, &private));

    OptimisedPromoKeypair { private, public, code: promo_code }
}