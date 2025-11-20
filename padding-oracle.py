import sys
from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this is 16 bytes"

CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:

    if len(ciphertext) % BLOCK_SIZE != 0:
        return False
    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        if not ct: # Handle empty ciphertext case
            return False
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    if len(data) % block_size != 0:
        raise ValueError(f"Data length {len(data)} is not a multiple of block size {block_size}")
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:

    if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
        raise ValueError("Blocks must be of BLOCK_SIZE")

    intermediate_state = bytearray(BLOCK_SIZE)
    decrypted_block = bytearray(BLOCK_SIZE)

    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - byte_index

        forged_suffix = bytearray(padding_val - 1)
        for i in range(len(forged_suffix)):
            pos = byte_index + 1 + i
            forged_suffix[i] = intermediate_state[pos] ^ padding_val

        found_byte = False
        for guess in range(256):
            prefix_len = byte_index
            forged_iv = (
                    b'\x00' * prefix_len +
                    bytes([guess]) +
                    forged_suffix
            )

            test_ciphertext = forged_iv + target_block

            if padding_oracle(test_ciphertext):
                intermediate_state[byte_index] = guess ^ padding_val

                decrypted_block[byte_index] = intermediate_state[byte_index] ^ prev_block[byte_index]

                sys.stdout.write(f"\r[*] Decrypting block... Bytes found: {BLOCK_SIZE - byte_index}/{BLOCK_SIZE}")
                sys.stdout.flush()

                found_byte = True
                break

        if not found_byte:
            raise RuntimeError(f"Could not find a valid byte at index {byte_index}")

    print()
    return bytes(decrypted_block)

def padding_oracle_attack(ciphertext: bytes) -> bytes:
    blocks = split_blocks(ciphertext)
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]

    recovered_plaintext = b""

    prev_block = iv

    for i, target_block in enumerate(ciphertext_blocks):
        print(f"\n[+] Attacking Block {i+1}/{len(ciphertext_blocks)}")
        decrypted_block = decrypt_block(prev_block, target_block)
        recovered_plaintext += decrypted_block

        prev_block = target_block
    return recovered_plaintext

def unpad_and_decode(plaintext: bytes) -> str:
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded_data = unpadder.update(plaintext) + unpadder.finalize()
        return unpadded_data.decode('utf-8')
    except (ValueError, UnicodeDecodeError) as e:
        print(f"[!] Error during unpadding or decoding: {e}")
        print("[!] Returning raw unpadded bytes as a fallback.")
        return str(unpadded_data)


if __name__ == "__main__":
    try:
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        decoded = unpad_and_decode(recovered)
        print("\n Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n Error occurred: {e}")
