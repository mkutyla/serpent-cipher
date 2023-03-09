from typing import List


def text_to_bin(text: str):
    return ''.join(resize(format(ord(x), 'b'), 8) for x in text)


def decode_binary_string(s):
    return ''.join(chr(int(s[i * 8:i * 8 + 8], 2)) for i in range(len(s) // 8))


def xor_binary(block, key):
    # result = block ^ key

    result = ""
    for i in range(len(block)):
        if block[i] == key[i]:
            result += "0"
        else:
            result += "1"

    return result


def hex_to_bin(text: str):
    # split the text into 8 bit hex numbers, each representing a single character
    text = string_split(text, 2)
    output = ''
    for hex_number in text:
        output += resize((bin(int(hex_number, 16))[2:]), 8)
    return output


def bin_to_hex(text: str):
    text = string_split(text, 8)
    output = ''
    for bin_number in text:
        output += resize((hex(int(bin_number, 2))[2:]), 2)
    return output


# adds leading zero's until text's length matches passed length
def resize(text: str, length: int) -> str:
    while len(text) < length:
        text = '0' + text
    return text


def xor(*args):
    result = args[0]
    for arg in args[1:]:
        result = xor_binary(result, arg)
    return result


def string_split(text: str, block_size: int) -> List[str]:
    while len(text) % block_size:
        text += '0'

    return [text[i:i + block_size] for i in range(0, len(text), block_size)]


def rotl(text: str, n: int):
    n = n % len(text)
    return text[-n:] + text[:-n]


def lshift(text: str, n: int):
    return "0" * len(text[-n:]) + text[:-n]


def char_swap(text: str, change: str, n: int):
    if n >= len(text): return
    return text[:n] + change + text[n + 1:]


def serpent_bin(n: int, length: int):
    return resize(bin(n)[2:], length)[::-1]
