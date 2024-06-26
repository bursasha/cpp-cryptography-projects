#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

// ---------------------------------------------------------------------------------------------------------------------

#include <openssl/evp.h>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------------------------------------------------

using namespace std;

// =====================================================================================================================

// Structure to hold cryptographic configuration including function name, key, IV, and their lengths.
struct crypto_config
{
	const char * m_crypto_function; // Name of the cryptographic function (e.g., AES-128-ECB)
	std::unique_ptr<uint8_t[]> m_key; // Pointer to the encryption/decryption key
	std::unique_ptr<uint8_t[]> m_IV; // Pointer to the Initialization Vector (IV)
	size_t m_key_len; // Length of the key
	size_t m_IV_len; // Length of the IV
};

// =====================================================================================================================

/**
 * Control and generate the cryptographic key and IV if needed.
 *
 * @param to_encrypt Boolean flag indicating whether to generate new key and IV (true for encryption).
 * @param config Reference to the crypto_config structure holding the configuration.
 * @param cipher_type The cipher type (e.g., AES-128-ECB) to be used.
 *
 * @return True if the key and IV are valid and ready for use, false otherwise.
 */
bool control_config ( const bool to_encrypt, crypto_config & config, const EVP_CIPHER * cipher_type )
{
	auto cipher_key_length = size_t (EVP_CIPHER_key_length (cipher_type)),
				 cipher_iv_length = size_t (EVP_CIPHER_iv_length (cipher_type));

	if (!config.m_key || config.m_key_len < cipher_key_length)
	{
		if (!to_encrypt) return false;

		config.m_key = std::make_unique <uint8_t []> (cipher_key_length);

		if (!RAND_bytes (config.m_key.get (), int (cipher_key_length))) return false;
		else config.m_key_len = cipher_key_length;
	}

	if (cipher_iv_length && (!config.m_IV || config.m_IV_len < cipher_iv_length))
	{
		if (!to_encrypt) return false;

		config.m_IV = std::make_unique <uint8_t []> (cipher_iv_length);

		if (!RAND_bytes (config.m_IV.get (), int (cipher_iv_length))) return false;
		else config.m_IV_len = cipher_iv_length;
	}

	return true;
}

// =====================================================================================================================

/**
 * Read data from an input file into a buffer.
 *
 * @param processed_size Reference to an integer holding the size of data processed.
 * @param input_file Reference to the input file stream.
 * @param buffer Pointer to the buffer where data will be read.
 *
 * @return True if the read operation is successful, false otherwise.
 */
bool read_data ( int & processed_size, std::ifstream & input_file, uint8_t * buffer )
{
	input_file.read ((char *) (buffer), processed_size);
	processed_size = int (input_file.gcount ());

	return !input_file.bad ();
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Write data from a buffer to an output file.
 *
 * @param processed_size The size of data processed.
 * @param output_file Reference to the output file stream.
 * @param buffer Pointer to the buffer where data will be written from.
 *
 * @return True if the write operation is successful, false otherwise.
 */
bool write_data ( const int processed_size, std::ofstream & output_file, uint8_t * buffer )
{
	output_file.write ((char *) (buffer), processed_size);

	return !output_file.bad ();
}

// =====================================================================================================================

/**
 * Encrypt or decrypt data from an input file and write the result to an output file.
 *
 * @param to_encrypt Boolean flag indicating whether to encrypt (true) or decrypt (false).
 * @param input_file Reference to the input file stream.
 * @param output_file Reference to the output file stream.
 * @param config Reference to the crypto_config structure holding the configuration.
 * @param cipher_type The cipher type (e.g., AES-128-ECB) to be used.
 * @param context Pointer to the EVP_CIPHER_CTX context structure.
 *
 * @return True if the operation is successful, false otherwise.
 */
bool convert_data ( const bool to_encrypt, std::ifstream & input_file, std::ofstream & output_file,
					crypto_config & config, const EVP_CIPHER * cipher_type, EVP_CIPHER_CTX * context )
{
	const int HEADERSIZE = 18, BUFFERSIZE = 8192;
	int header_processed_size = HEADERSIZE, input_processed_size = BUFFERSIZE, output_processed_size;
	uint8_t header_buffer[HEADERSIZE], input_buffer[BUFFERSIZE], output_buffer[BUFFERSIZE + EVP_MAX_BLOCK_LENGTH];

	if (!EVP_CipherInit (context, cipher_type, config.m_key.get (), config.m_IV.get (), to_encrypt) ||
		!read_data (header_processed_size, input_file, header_buffer) ||
		header_processed_size != HEADERSIZE ||
		!write_data (header_processed_size, output_file, header_buffer))
		return false;

	while (!input_file.eof ())
	{
		if (!read_data (input_processed_size, input_file, input_buffer) ||
		    !EVP_CipherUpdate (context, output_buffer, & output_processed_size, input_buffer, input_processed_size) ||
		    !write_data (output_processed_size, output_file, output_buffer))
			return false;
	}

	if (!EVP_CipherFinal_ex (context, output_buffer, & output_processed_size) || !write_data (output_processed_size, output_file, output_buffer))
		return false;

	return true;
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Handle the encryption or decryption process using the specified configuration.
 *
 * @param to_encrypt Boolean flag indicating whether to encrypt (true) or decrypt (false).
 * @param in_filename Reference to the input filename.
 * @param out_filename Reference to the output filename.
 * @param config Reference to the crypto_config structure holding the configuration.
 *
 * @return True if the process is successful, false otherwise.
 */
bool process_data ( const bool to_encrypt, const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	ifstream input_file (in_filename,ios::binary); ofstream output_file (out_filename,ios::binary);
	if (input_file.fail () || !(input_file.is_open ()) || output_file.fail () || !(output_file.is_open ())) return false;

	OpenSSL_add_all_ciphers ();
	EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new ();
	const EVP_CIPHER * cipher_type = EVP_get_cipherbyname (config.m_crypto_function);

	bool convertion_successful =
			(config.m_crypto_function && context && cipher_type &&
			control_config (to_encrypt, config, cipher_type) &&
			convert_data (to_encrypt, input_file, output_file, config, cipher_type, context));

	EVP_CIPHER_CTX_free (context); input_file.close (); output_file.close ();

	return convertion_successful;
}

// =====================================================================================================================

/**
 * Wrapper function to encrypt data using the specified configuration.
 *
 * @param in_filename Reference to the input filename.
 * @param out_filename Reference to the output filename.
 * @param config Reference to the crypto_config structure holding the configuration.
 *
 * @return True if the encryption is successful, false otherwise.
 */
bool encrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	return process_data (true, in_filename, out_filename, config);
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * Wrapper function to decrypt data using the specified configuration.
 *
 * @param in_filename Reference to the input filename.
 * @param out_filename Reference to the output filename.
 * @param config Reference to the crypto_config structure holding the configuration.
 *
 * @return True if the decryption is successful, false otherwise.
 */
bool decrypt_data ( const std::string & in_filename, const std::string & out_filename, crypto_config & config )
{
	return process_data (false, in_filename, out_filename, config);
}

// =====================================================================================================================

/**
 * Compare two files byte by byte to check if they are identical.
 *
 * @param name1 Pointer to the first file's name.
 * @param name2 Pointer to the second file's name.
 *
 * @return True if the files are identical, false otherwise.
 */
bool compare_files ( const char * name1, const char * name2 )
{
	ifstream file1 (name1, ios::binary), file2 (name2, ios::binary);
	if (file1.fail () || !(file1.is_open ()) || file2.fail () || !(file2.is_open ())) { file1.close (); file2.close (); return false; }

	while ((!file1.eof ()) && (!file2.eof ()))
	{
		string line1, line2;
		getline (file1, line1); getline (file2, line2);
		if (line1 != line2) { file1.close (); file2.close (); return false; }

		file1.close (); file2.close ();
	}

	return true;
}

// =====================================================================================================================

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
