The attack decrypts a given ciphertext without knowing the encryption key, by repeatedly querying a server (the "oracle") that only reveals whether a submitted ciphertext has valid PKCS#7 padding.


1.  Ensure you have Python 3 and the `cryptography` library installed:
    ```bash
    pip install cryptography
    ```
2.  Run the script from your terminal:
    ```bash
    python padding_oracle_lab.py
    ```
The script will print its progress as it decrypts the ciphertext block by block.


**1. Analyze the `padding_oracle` function. How does it determine if padding is valid?**

The `padding_oracle` function determines padding validity by exploiting exception handling. It works as follows:
1.  It takes a ciphertext, separates the IV and the encrypted blocks, and attempts to decrypt the data using the provided `KEY`.
2.  After decryption, it uses the `cryptography.hazmat.primitives.padding.PKCS7` unpadder.
3.  The critical step is `unpadder.finalize()`. This method will raise a `ValueError` if the decrypted plaintext does not end with a valid PKCS#7 padding sequence (e.g., `...03 03 03`, `...08 08 08 08 08 08 08 08`, etc.).
4.  The entire process is wrapped in a `try...except (ValueError, TypeError)` block. If a `ValueError` is raised during `finalize()`, the `except` block catches it and the function returns `False`, indicating invalid padding.
5.  If the decryption and unpadding complete without any exceptions, the function returns `True`, indicating the padding was valid.

**2. What is the purpose of the IV in CBC mode?**

The Initialization Vector (IV) is a random block of data with the same size as the cipher's block size. Its purpose in Cipher Block Chaining (CBC) mode is to ensure **semantic security**. 
It introduces randomness into the encryption process so that encrypting the same plaintext multiple times with the same key will produce different ciphertexts.

In CBC decryption, the IV is XORed with the result of decrypting the *first* ciphertext block to produce the first plaintext block. For all subsequent blocks, the *previous* ciphertext block acts as the "IV" for the current block.

**3. Why does the ciphertext need to be a multiple of the block size?**

Block ciphers like AES operate on fixed-size blocks of data (16 bytes in this case). CBC mode is a method for securely encrypting a sequence of these blocks.
*   **Encryption:** The plaintext is first padded to ensure its length is a multiple of the block size.
*   Then, it's broken into blocks, and the CBC encryption process is applied block by block. The resulting ciphertext is naturally a sequence of full-sized blocks.
*   **Decryption:** The decryption process likewise expects to receive a sequence of full-sized blocks.
*   The `padding_oracle` function explicitly checks this with `if len(ciphertext) % BLOCK_SIZE != 0: return False` as a preliminary sanity check, because a valid CBC-encrypted message will always have this property.

## Observations and Challenges

*   **Attack Granularity:** The most interesting observation is how a single bit of information leak ("valid padding" or "invalid padding") can be leveraged to fully compromise the confidentiality of the entire message.
*   **Performance:** The attack is methodical but slow. For each byte of plaintext, it may need to make up to 256 requests to the oracle in the worst case. For a 16-byte block, this is up to 4096 requests.
*   This highlights that while powerful, the attack is not instantaneous and can be detected through monitoring.
*   **Implementation Challenge:** The core challenge was correctly implementing the logic inside the `decrypt_block` function.
* It is critical to correctly construct the "forged IV" by manipulating the bytes that have already been solved to produce the desired padding value.
* A small mistake in the XOR logic (`intermediate_state[pos] ^ padding_val`) would cause the attack to fail for subsequent bytes. Visualizing the CBC decryption diagram was essential to getting this right.
