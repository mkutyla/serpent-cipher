from binary_strings import *
from serpent_constants import *
import argparse

parser = argparse.ArgumentParser(
    description="encrypts/decrypts passed text with given key using Serpent Cipher")

mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('-e', "--encrypt", action='store_true',
                  help="encryption mode")
mode.add_argument('-d', "--decrypt", action='store_true',
                  help="decryption mode")

group_text = parser.add_mutually_exclusive_group()
group_text.add_argument("-tb", "--text_binary", required=False, action="store_true",
                        help="indicates that text is in binary format")
group_text.add_argument("-tx", "--text_hex", required=False, action="store_true",
                        help="indicates that text is in hexadecimal format")
parser.add_argument(
    'text', type=str, help="text to encrypt/decrypt (default format: UTF)")

group_key = parser.add_mutually_exclusive_group()
group_key.add_argument("-ku", "--key_utf", required=False, action="store_true",
                       help="indicates that key is in UTF format")
group_key.add_argument("-kb", "--key_binary", required=False, action="store_true",
                       help="indicates that key is in binary format")
parser.add_argument('key', type=str, help="key (default format: hexadecimal)")


def encrypt(plain_text: str, key: str) -> str:
    if len(plain_text) != 128:
        raise ValueError("Invalid plain_text length")

    key = make_long_key(key)
    round_keys = make_subkeys(key)

    block = permutation(IPTable, plain_text)  # init permutation: B0
    for r in range(0, ROUNDS - 1):  # i =  0, ..., 30
        block = linear_transform(LTable, sub_box(
            SBox, r, xor(block, round_keys[r])))

    block = xor(sub_box(SBox, 31, xor(block, round_keys[31])), round_keys[32])

    cipher_text = permutation(FPTable, block)  # finishing permutation

    return cipher_text


def decrypt(cipher_text: str, key: str) -> str:
    if len(cipher_text) != 128:
        raise ValueError("Invalid cipher_text length")

    key = make_long_key(key)
    round_keys = make_subkeys(key)
    block = permutation(IPTable, cipher_text)  # finishing permutation inversed
    block = xor(sub_box(InvSbox, 31, xor(
        block, round_keys[32])), round_keys[31])

    for i in range(ROUNDS - 2, -1, -1):  # i = 30
        block = xor(sub_box(InvSbox, i, linear_transform(
            InvLTable, block)), round_keys[i])

    plain_text = permutation(FPTable, block)

    return plain_text


def permutation(permutation_table, block: str) -> str:
    if len(block) != len(permutation_table):
        raise ValueError("Invalid block length")

    result = ''
    for i in range(len(permutation_table)):
        result += block[permutation_table[i]]

    return result


# Extends given 128- or 192-bit key into a 256-bit key
def make_long_key(key):
    length = len(key)

    if length == 256:
        return key

    if length != 128 and length != 192:
        raise ValueError

    key += '1'
    while len(key) != 256:
        key += '0'

    return key


def make_subkeys(key: str) -> List[str]:
    if len(key) != 256:
        raise ValueError("Invalid key length")

    prekeys = []
    # splitting passed key into 8 32-bit words
    for i in range(8):
        prekeys.append(key[i * 32:(i + 1) * 32])

    # generating 132 prekeys
    for i in range(8, 140):
        prekeys.append(
            rotl(xor(prekeys[i - 8], prekeys[i - 5], prekeys[i - 3], prekeys[i - 1],
                     PHI, serpent_bin(i - 8, 32)), 11))

    # removing excess prekeys
    prekeys = prekeys[8:]
    round_keys = []
    for i in range(0, 132, 4):
        _ = [''] * 4
        for j in range(32):
            out = serpent_bin(SBox[(3 - i // 4) % 8]
                              [int(prekeys[i + 3][j] + prekeys[i + 2][j] + prekeys[i + 1][j] + prekeys[i][j], 2)
                               ], 4)
            for l in range(4):
                _[l] += out[l]

        round_keys.append(''.join(_))

    return round_keys


def sub_box(box, round_number: int, block: str) -> str:
    if len(block) != 128:
        raise ValueError("Invalid block length")

    result = ''
    # parallel usage of correct S-box 32 times
    for i in range(0, 128, 4):
        result = result + \
            resize(bin(box[round_number % 8]
                   [int(block[i:i + 4][::-1], 2)])[2:], 4)[::-1]

    return result


def linear_transform(table, block: str) -> str:
    if len(block) != 128:
        raise ValueError("Invalid block length")

    output = ''
    for i in range(128):
        output += xor(*[block[n] for n in table[i]])

    return output


if __name__ == "__main__":
    args = parser.parse_args()

    if args.text_binary:
        text = args.text
    elif args.text_hex:
        text = hex_to_bin(args.text)
    else:
        text = text_to_bin(args.text)

    if args.key_utf:
        key = text_to_bin(args.key)
    elif args.key_binary:
        key = args.key
    else:
        key = hex_to_bin(args.key)

    if args.encrypt:
        print(bin_to_hex(encrypt(text, key)))
    else:
        print(decode_binary_string(decrypt(text, key)))
