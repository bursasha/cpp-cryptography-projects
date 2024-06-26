# **Cryptography and Security University Projects** 🔒

## **Repository Overview** 📄
This repository contains various university projects focused on cryptography and security concepts, 
implementing both theoretical and practical tasks learned during the course. 
The projects demonstrate the application of cryptographic techniques using **C++** and the **`OpenSSL`** library.

## **Repository Structure** 📂
- **`EncryptionModes/`**: Contains projects related to different encryption modes (e.g., ECB, CBC).
- **`Hash/`**: Contains projects related to hash functions and their applications.
- **`HybridEncryption/`**: Contains projects combining multiple cryptographic techniques (e.g., hybrid encryption).
- **`README.md`**: The main README file providing an overview of the repository.

## **Course Description** 📚
The **"Cryptography and Security"** course covers a comprehensive range of topics in cryptography, 
both from a theoretical and practical perspective. 
The following topics are the primary focus:
- **Basic Concepts in Cryptology**:
    - Substitution ciphers, block ciphers, polyalphabetic ciphers, transposition ciphers.
    - Reliability assessment of encryption systems.
- **Classical Cryptanalysis**:
    - Hill cipher, Vigenère cipher, frequency analysis.
- **Modern Cryptography**:
    - Block ciphers (DES, TripleDES, AES), stream ciphers (Salsa20, Chacha, A5/1).
    - Modes of operation (ECB, CBC), message authentication codes (MAC).
- **Hash Functions**:
    - One-way functions, collision resistance, birthday paradox.
    - Modern hash functions (SHA-1, SHA-256), HMAC.
- **Asymmetric Cryptography**:
    - RSA, key generation, encryption, and authentication.
    - El Gamal cipher, digital signatures.
- **Smart Card Security**:
    - Authentication factors, smart card interfaces, internal composition.
    - Symmetric and asymmetric cryptography, secure communication.
- **Cryptographic Security Evaluation**:
    - Theoretical, unconditional, conditional, provable, and computational security.
    - Kerckhoffs principle, entropy, language redundancy, unicity distance.
- **Elliptic Curve Cryptography**:
    - Elliptic curves in cryptography, discrete logarithm problem.
    - Diffie-Hellman on elliptic curves, quantum cryptography basics.
- **Number Theory and Randomness**:
    - Chinese remainder theorem, Rabin-Miller primality test.
    - Pseudorandom generators, true random generators, entropy sources.
    - Random generator testing (frequency test, Runs test, matrix rank test).
- **Key Distribution and Management**:
    - Public and secret key distribution methods, public key certification.
    - Certificate properties, certification authorities, certificate chains.

## **Key Projects and Their Purpose** 📌

### 1. **EncryptionModes**:
- Demonstrates the implementation of different encryption modes using the AES-128 cipher in ECB and CBC modes.
- Key functionalities include encryption, decryption, and file comparison to ensure data integrity.

### 2. **Hash**:
- Focuses on hash functions, including their implementation and verification.
- Projects include generating hash values, verifying their properties, and exploring collision resistance.

### 3. **HybridEncryption**:
- Combines multiple cryptographic techniques to implement secure communication.
- Projects may include hybrid encryption schemes that use both symmetric and asymmetric cryptography for enhanced security.

## **Tools and Techniques Used** 🛠️
- **OpenSSL**:
    - Utilized for cryptographic functions such as encryption, decryption, and hashing.
    - Key functions include `EVP_CipherInit`, `EVP_CipherUpdate`, `EVP_CipherFinal_ex`, and various hash functions.
- **C++ Standard Library**:
    - Memory management using smart pointers (`std::unique_ptr`).
    - File I/O operations for reading and writing binary data.
    - String manipulation and standard algorithms for processing data.
- **Error Handling**:
    - Ensuring successful allocation of memory and validating the success of cryptographic operations.
    - Cleaning up resources in case of failure to prevent memory leaks.

## **Concepts Applied** 📚
- **Encryption and Decryption**:
    - Implementing AES-128 in ECB and CBC modes for secure data encryption and decryption.
- **Hash Functions**:
    - Generating and verifying hash values using SHA-512 and ensuring collision resistance.
- **Hybrid Encryption**:
    - Combining symmetric and asymmetric cryptography to achieve secure communication.
- **File Comparison**:
    - Byte-by-byte comparison of files to ensure data integrity after cryptographic operations.
- **Memory Management**:
    - Proper allocation and deallocation of resources to ensure no memory leaks during cryptographic operations.

## **Conclusion** 📝
This repository showcases a variety of cryptographic projects developed as part of the **"Cryptography and Security"** university course. 
It demonstrates the practical application of cryptographic techniques using **C++** and `OpenSSL`, providing a strong foundation in both theoretical and practical aspects of modern cryptography.