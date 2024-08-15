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

VanityGen supports an alternative "promos" mode in which the tool guides you through a step-by-step PIVX Promos batching process - whether it's a single code, or 10,000 codes, the process is the same.

```bash
# Startup in to Promos mode
--promos
```

After which, the tool will ask you a series of questions to construct your batch of PIVX Promo codes, for example:
```
% ./pivx-vanity --promos
Would you like to save your batch as a CSV file?
Y/n: Y

What would you like to name it? (default: "promos")
promos: test

Perfect, now, let's start planning your batch!
----------------------------------------------
Batch 1: how many codes do you want? (default: "5")
5: 5

Batch 1: how much PIV should each of your 5 codes be worth? (default: "1")
1: 25

----------------------------------------------
 - Batch 1: 5 codes of 25 PIV
... for a total of 5 codes worth 125 PIV
----------------------------------------------
Would you like to add another batch?
y/N: N

What prefix would you like to use? For example: promos-QDmes (default: "promos")
promos: jskitty

Time to begin! Please do NOT cancel or interfere with the generation process!
Generating...
Code 1 of batch 1: Promo: 'jskitty-o3QAi' - Address: D6RYFELVRb3gcLUqoVMioMyJfjJ1X4e6ww - WIF: YUAZnZPKGQGWeiMfrxQNjSiUqexAVyiddcaeUZNdncaX4brVj21g
 - Filling with 25 PIV...
 - TX: ...
```
