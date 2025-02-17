[![Documentation Status](https://readthedocs.org/projects/crypt4gh/badge/?version=latest)](https://crypt4gh.readthedocs.io/en/latest/?badge=latest)
[![Testsuite](https://github.com/EGA-archive/crypt4gh/workflows/Testsuite/badge.svg)](https://github.com/EGA-archive/crypt4gh/actions)

# Crypt4GH Encryption Utility

`crypt4gh`is a Python tool to encrypt, decrypt or re-encrypt files, according to the [GA4GH encryption file format](https://www.ga4gh.org/news/crypt4gh-a-secure-method-for-sharing-human-genetic-data/). 

This is a modified version developed at the Cologne Center for Genomics (CCG) which extends the crypt4gh's capabilities to deal with lists of input/output data and offers the possibility of splitting the headers from the encrypted files (.c4gh) and store them in a separate (.hd) file (using the --split-header flag). 


## Installation

Python `3.6+` required to use the crypt4gh encryption utility.


You can install the lastest version from Github:

```
git clone https://github.com/EGA-archive/crypt4gh
pip install -r crypt4gh/requirements.txt
pip install ./crypt4gh
```


## Usage

The usual `-h` flag shows you the different options that the tool accepts.

```bash
$ crypt4gh -h

Usage:
  crypt4gh [-hv] [--log <file>] encrypt [--sk <path>] (--inputfile <path> | --inputfilelist <path>) --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>] [--split-header] 
  crypt4gh [-hv] [--log <file>] decrypt [--sk <path>] (--inputfile <path> | --inputfilelist <path>) [--sender_pk <path>] [--range <start-end>] [--split-header]
   crypt4gh [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   crypt4gh [-hv] [--log <file>] reencryptfile [--sk <path>] --recipient_pk <path> (--inputfile <path>|--inputfilelist <path>) (--outputfile <path>|--outputfilelist <path>) [--recipient_pk <path>]... [--trim] 
   crypt4gh [-hv] [--log <file>] reencryptheader [--sk <path>] --recipient_pk <path> (--inputheader <path>|--inputheaderlist <path>) (--outputheader <path>|--outputheaderlist <path>) [--recipient_pk <path>]... [--trim] 

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <path>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key
                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
   --inputfile <path>     Input file to be encrypted/decrypted
   --inputfilelist <path> Input file list to be encrypted/decrypted
   --inputheader <path>   Input header  to be encrypted/decrypted
   --inputheaderlist <path>   Input header list to be encrypted/decrypted
   --outputfile <path>    Output file 
   --outputfilelist <path>    Output file list
   --outputheader <path>  Output header file
   --outputheaderlist <path>  Output header file list
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt
   --split-header         Separate the header from the payload during encryption and create a separate .header file

Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${C4GH_SECRET_KEY})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
   C4GH_DEBUG       If True, it will print (a lot of) debug information.
                    (Watch out: the output contains secrets)
 
```

## Demonstration

Alice and Bob generate both a pair of public/private keys.

```bash
$ crypt4gh-keygen --sk alice.sec --pk alice.pub
$ crypt4gh-keygen --sk bob.sec --pk bob.pub
```

Bob encrypts a file for Alice:

```bash
$ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub --inputfile file --split-header
```

Bob encrypts a list of files for Alice:

```bash
$ crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub --inputfilelist files.lst --split-header
```


Alice decrypts the encrypted file:

```bash
$ crypt4gh decrypt --sk alice.sec --inputfile file.c4gh --split-header
```

Alice decrypts a list of encrypted files:

```bash
$ crypt4gh decrypt --sk alice.sec --inputfilelist encryptedfiles.lst --split-header
```

[![asciicast](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs.svg)](https://asciinema.org/a/mmCBfBdCFfcYCRBuTSe3kjCFs)

## File Format

Refer to the [specifications](http://samtools.github.io/hts-specs/crypt4gh.pdf) or this [documentation](https://crypt4gh.readthedocs.io/en/latest/encryption.html).
