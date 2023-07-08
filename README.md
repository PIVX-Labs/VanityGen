# VanityGen
Powerful PIVX VanityGen written in Rust.

## VanityGen Usage
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

## PIVX Promos Usage

As well as having VanityGen: this binary supports PIVX Promos!

To create a PIVX Promos code, simply specify the quantity of codes to create, and VanityGen will shift to generating Promo Codes, ignoring VanitGen commands.

```bash
# Choose the quantity of codes to create: if not specified, VanityGen is used
--promo-count=<int> # example: --promo-count=6

# Choose a prefix for your PIVX Promo code: defaults to "PIVX Labs"
--promo-prefix="<string>" # example: --promo-prefix="I love PIVX!"
```

A full example may look like:
```
./pivx-vanity --promo-count=1 --promo-prefix="JSKitty is awesome"
```