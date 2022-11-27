# `ntru`

Simple & insecure NTRUEncrypt CLI

**WARNING: DO NOT USE IN PRODUCTION, THIS TOOL HAS BEEN CREATED FOR EDUCATIONAL PURPOSES ONLY!**

## Install

1. Install Rust: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
2. Run `cargo install --git https://github.com/sv512/ntru`
3. See possible commands using `ntru -h`

## Usage

You can test the following commands from the `test/` directory:

```sh
# generate key pair
ntru gen

# generate new public key
ntru gen key/private.txt

# encrypt file.txt
ntru enc file.txt key/public.txt

# decrypt file.txt
ntru dec file.txt key/private.txt key/public.txt

# show general information about backend & ntru parameters
ntru info
```

For more information, see: `ntru -h`

## Limitations

- The plaintext files must be smaller or equal to 186 bytes in size (see `ntru info`)
- The NTRU parameters can't be changed
