# VanityGen
Powerful PIVX VanityGen written in Rust.

## Usage
```bash
# Choose a target prefix for your address: defaults to "D" for non-vanity mode
--target="D<string>" # example: --target=DLabs
    
# Choose the threads to run at: defaults to maximum cores
--threads=<int> # example: --threads=6
    
# Case Insensitivity: use this flag to disable case sensitivity for faster searches
--case-insensitive
```

A full example may look like:
```
./pivx-vanity --case-insensitive --threads=6 --target=DLabs
```
