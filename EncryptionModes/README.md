# **Image File Encryption and Decryption using OpenSSL** 🔒

## **Overview** 📄
This project provides a C++ implementation for encrypting and decrypting image files using the **`OpenSSL`** library. 
It demonstrates how to securely handle data encryption and decryption using **AES-128** in **ECB** and **CBC** modes.

## **Key Functions and Their Purpose** 📌

### 1. **`control_config`**:
- Generates and validates the cryptographic key and Initialization Vector (IV) as needed.
- Parameters:
    - `to_encrypt`: Boolean flag indicating whether to generate new key and IV (true for encryption).
    - `config`: Reference to the `crypto_config` structure holding the configuration.
    - `cipher_type`: The cipher type (e.g., AES-128-ECB) to be used.
- Returns `true` if the key and IV are valid and ready for use, `false` otherwise.
### 2. **`read_data`**:
- Reads data from an input file into a buffer.
- Parameters:
    - `processed_size`: Reference to an integer holding the size of data processed.
    - `input_file`: Reference to the input file stream.
    - `buffer`: Pointer to the buffer where data will be read.
- Returns `true` if the read operation is successful, `false` otherwise.

### 3. **`write_data`**:
- Writes data from a buffer to an output file.
- Parameters:
    - `processed_size`: The size of data processed.
    - `output_file`: Reference to the output file stream.
    - `buffer`: Pointer to the buffer where data will be written from.
- Returns `true` if the write operation is successful, `false` otherwise.

### 4. **`convert_data`**:
- Encrypts or decrypts data from an input file and writes the result to an output file.
- Parameters:
    - `to_encrypt`: Boolean flag indicating whether to encrypt (true) or decrypt (false).
    - `input_file`: Reference to the input file stream.
    - `output_file`: Reference to the output file stream.
    - `config`: Reference to the `crypto_config` structure holding the configuration.
    - `cipher_type`: The cipher type (e.g., AES-128-ECB) to be used.
    - `context`: Pointer to the `EVP_CIPHER_CTX` context structure.
- Returns `true` if the operation is successful, `false` otherwise.

### 5. **`process_data`**:
- Handles the encryption or decryption process using the specified configuration.
- Parameters:
    - `to_encrypt`: Boolean flag indicating whether to encrypt (true) or decrypt (false).
    - `in_filename`: Reference to the input filename.
    - `out_filename`: Reference to the output filename.
    - `config`: Reference to the `crypto_config` structure holding the configuration.
- Returns `true` if the process is successful, `false` otherwise.

### 6. **`encrypt_data`**:
- Wrapper function to encrypt data using the specified configuration.
- Parameters:
    - `in_filename`: Reference to the input filename.
    - `out_filename`: Reference to the output filename.
    - `config`: Reference to the `crypto_config` structure holding the configuration.
- Returns `true` if the encryption is successful, `false` otherwise.

### 7. **`decrypt_data`**:
- Wrapper function to decrypt data using the specified configuration.
- Parameters:
    - `in_filename`: Reference to the input filename.
    - `out_filename`: Reference to the output filename.
    - `config`: Reference to the `crypto_config` structure holding the configuration.
- Returns `true` if the decryption is successful, `false` otherwise.

### 8. **`compare_files`**:
- Compares two files byte by byte to check if they are identical.
- Parameters:
    - `name1`: Pointer to the first file's name.
    - `name2`: Pointer to the second file's name.
- Returns `true` if the files are identical, `false` otherwise.

## **Usage Example** 📘
```cpp
int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
	        compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
	        compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
	        compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
	        compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
	        compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );

	return 0;
}
```

## **Tools and Techniques Used** 🛠️
- **OpenSSL**:
    - Utilized for cryptographic functions, including encryption and decryption.
    - Key functions include `EVP_CipherInit`, `EVP_CipherUpdate`, and `EVP_CipherFinal_ex` for encryption/decryption operations.
- **C++ Standard Library**:
    - Memory management using `std::unique_ptr`.
    - File I/O operations for reading and writing binary data.
    - String manipulation and standard algorithms.
- **Error Handling**:
    - Ensuring successful allocation of memory.
    - Validating the success of cryptographic operations.
    - Cleaning up resources in case of failure to prevent memory leaks.

## **Concepts Applied** 📚
- **Encryption and Decryption**:
    - Using **AES-128** in **ECB** and **CBC** modes to securely encrypt and decrypt image files.
- **File Comparison**:
    - Byte-by-byte comparison of files to ensure data integrity after encryption and decryption.
- **Memory Management**:
    - Proper allocation and deallocation of resources to ensure no memory leaks.

## **Conclusion** 📝
This project demonstrates how to securely encrypt and decrypt image files using the `OpenSSL` library in C++, 
showcasing the integration of cryptographic techniques with standard C++ programming practices.
