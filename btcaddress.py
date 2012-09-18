import hashlib
import key

"""This module is used to create new (random) bitcoin addresses.

To use it call create_new_address(testnet). Testnet is a bool indicating if you
want to make an address to be used on the testnet or on the main bitcoin
network.

This method will return a tuple of two strings. The first string is the private
key, base58 encoded and can be imported in bitcoin using the importprivkey RPC
call. The other string is the bitcoin address."""

###############################################################################
# Various hashing and encoding functions.
###############################################################################

def ripemd160(string):
    """Calculates the ripemd160 hash of string and returns it."""
    md = hashlib.new("ripemd160")
    md.update(string)
    return md.digest()

def sha256(string):
    """Calculates the sha256 hash of a string and returns it."""
    md = hashlib.new("sha256")
    md.update(string)
    return md.digest()

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def base58encode(string):
    "Base58 encodes string"""
    long_value = 0L
    for (i, c) in enumerate(string[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in string:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def base58decode(v, length):
    """Decodes a base58 encoded string"""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base**i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]: nPad += 1
        else: break

    result = chr(0)*nPad + result
    if length is not None and len(result) != length:
        return None

    return result

def base58checksum_encode(secret):
    hash = sha256(sha256(secret))
    return base58encode(secret + hash[0:4])

def base58checksum_decode(sec):
    vchRet = base58decode(sec, None)
    secret = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = sha256(sha256(secret))
    cs32 = hash[0:4]
    if cs32 != csum:
        return None
    else:
        return secret



###############################################################################
# Conversion functions to convert openssl EC Keys to bitcoin addresses
###############################################################################

def ec_pubkey_to_btc_address(public_key, testnet):
    """Converts an EC public key to a bitcoin address.
    A bitcoin address consists of the following parts:
    -version: one byte, 0 for the mainnet, 111 for the testnet
    -hash: RIPEMD-160(SHA-256(public key))
    -checksum: first 4 bytes of SHA-256(SHA-256(version + hash))
    All those parts are concatenated together and the bitcoin address is the
    base58 encoding of this string.
    """

    if testnet:
        version = chr(111)
    else:
        version = chr(0)
    keyhash = ripemd160(sha256(public_key))
    address = version + keyhash
    return base58checksum_encode(address)

def ec_privkey_to_base58_privkey(private_key, testnet):
    """Converts a full private key as returned by OpenSSL and only takes the
    private key part out of it, base58 encoding it."""

    compressed = len(private_key) != 279
    if compressed:
        secret = private_key[8:8+32]
    else:
        secret = private_key[9:9+32]

    if testnet:
        vchin = chr((111 + 128) & 255) + secret
    else:
        vchin = chr((0 + 128) & 255) + secret

    if compressed:
        vchin += chr(1)

    checksum = sha256(sha256(vchin))[0:4]
    privkey = vchin + checksum
    return base58encode(privkey)


###############################################################################
# Main create_new_address() function
###############################################################################

def create_new_address(testnet):
    """Creates a new random bitcoin address."""
    #Creates a new EC Key
    eckey = key.CKey()
    eckey.generate()
    eckey.set_compressed(True)

    pubkey = eckey.get_pubkey()
    privkey = eckey.get_privkey()

    btcaddress = ec_pubkey_to_btc_address(pubkey, testnet)
    btcprivkey = ec_privkey_to_base58_privkey(privkey, testnet)
    return btcprivkey, btcaddress

if __name__ == "__main__":
    privkey, address = create_new_address(True)
    print "Bitcoin address:", address
    print "Base58 encoded private key:", privkey
