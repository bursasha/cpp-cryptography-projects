# **File Encryption and Decryption using OpenSSL** 🔒

## **Overview** 📄
This project provides a C++ implementation for _encrypting_ (sealing) and _decrypting_ (opening) files using **asymmetric encryption** with **`OpenSSL`**. 
It demonstrates how to securely encrypt data using a **public key** and decrypt it using the corresponding **private key**.

## **Key Functions and Their Purpose** 📌
### 1. **`read_data`**:
- Reads data from an input file stream into a buffer.
- Parameters:
    - `processed_size`: Size of data to be read, updated to the actual number of bytes read.
    - `in_file`: Input file stream to read from.
    - `buffer`: Buffer to store the read data.
- Returns `true` if reading is successful, `false` otherwise.

### 2. **`write_data`**:
- Writes data from a buffer to an output file stream.
- Parameters:
    - `processed_size`: Size of data to be written.
    - `out_file`: Output file stream to write to.
    - `buffer`: Buffer containing the data to write.
- Returns `true` if writing is successful, `false` otherwise.

### 3. **`seal_data`**:
- Encrypts (seals) data using a public key and a symmetric cipher.
- Parameters:
    - `in_file`: Input file stream containing the data to encrypt.
    - `out_file`: Output file stream to write the encrypted data.
    - `public_key`: Public key used for encryption.
    - `symmetric_cipher`: Name of the symmetric cipher to use.
    - `context`: Cipher context for encryption operations.
- Returns `true` if encryption is successful, `false` otherwise.

### 4. **`seal`**:
- Encrypts (seals) a file using a public key and a symmetric cipher.
- Parameters:
    - `in_filename`: Name of the input file to encrypt.
    - `out_filename`: Name of the output file to write the encrypted data.
    - `public_key_filename`: Name of the file containing the public key.
    - `symmetric_cipher`: Name of the symmetric cipher to use.
- Returns `true` if encryption is successful, `false` otherwise.

### 5. **`open_data`**:
- Decrypts (opens) data using a private key.
- Parameters:
    - `in_file`: Input file stream containing the encrypted data.
    - `out_file`: Output file stream to write the decrypted data.
    - `private_key`: Private key used for decryption.
    - `context`: Cipher context for decryption operations.
- Returns `true` if decryption is successful, `false` otherwise.

### 6. **`open`**:
- Decrypts (opens) a file using a private key.
- Parameters:
    - `in_filename`: Name of the input file to decrypt.
    - `out_filename`: Name of the output file to write the decrypted data.
    - `private_key_filename`: Name of the file containing the private key.
- Returns `true` if decryption is successful, `false` otherwise.

## **Usage Example** 📘
```cpp
int main() {
    assert(seal("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc"));
    assert(open("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem"));

    assert(open("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem"));

    return 0;
}
```

## **Tools and Techniques Used** 🛠️
- **`OpenSSL`**:
    - Utilized for cryptographic functions, including encryption and decryption.
    - Key functions include `EVP_SealInit`, `EVP_SealUpdate`, `EVP_SealFinal` for encryption, and `EVP_OpenInit`, `EVP_OpenUpdate`, `EVP_OpenFinal` for decryption.
- **C++ Standard Library**:
    - File handling using `ifstream` and `ofstream`.
    - Memory management using `malloc` and `free`.
    - String and stream manipulation.
- **Error Handling**:
    - Ensuring file streams are properly opened and closed.
    - Validating the success of cryptographic operations.
    - Cleaning up resources in case of failure to prevent memory leaks.

## **Concepts Applied** 📚
- **Asymmetric Encryption**:
    - Encrypting data with a **public key** and decrypting it with a **private key**.
- **Symmetric Encryption**:
    - Using a symmetric cipher (e.g., **AES-128-CBC**) for the actual data encryption and decryption.
- **Buffer Management**:
    - Reading and writing data in chunks to handle large files efficiently.
- **Resource Management**:
    - Proper allocation and deallocation of resources to ensure no memory leaks.

## **Conclusion** 📝
This project demonstrates how to implement file encryption and decryption in C++ using `OpenSSL`, 
showcasing the integration of cryptographic techniques with standard C++ file handling and memory management practices.
