#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

// ---------------------------------------------------------------------------------------------------------------------

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

// ---------------------------------------------------------------------------------------------------------------------

using namespace std;

// =====================================================================================================================

/**
 * @brief Reads data from the input file stream into the buffer.
 * @param processed_size Size of data to be read, updated to the actual number of bytes read.
 * @param in_file Input file stream to read from.
 * @param buffer Buffer to store the read data.
 * @return True if reading is successful, false otherwise.
 */
bool read_data ( int & processed_size, std::ifstream & in_file, unsigned char * buffer )
{
	in_file.read ((char *) (buffer), processed_size);
	processed_size = int (in_file.gcount ());
	return !in_file.bad ();
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * @brief Writes data from the buffer to the output file stream.
 * @param processed_size Size of data to be written.
 * @param out_file Output file stream to write to.
 * @param buffer Buffer containing the data to write.
 * @return True if writing is successful, false otherwise.
 */
bool write_data ( const int processed_size, std::ofstream & out_file, unsigned char * buffer )
{
	out_file.write ((char *) (buffer), processed_size);
	return !out_file.bad ();
}

// =====================================================================================================================

/**
 * @brief Encrypts (seals) data using a public key and a symmetric cipher.
 * @param in_file Input file stream containing the data to encrypt.
 * @param out_file Output file stream to write the encrypted data.
 * @param public_key Public key used for encryption.
 * @param symmetric_cipher Name of the symmetric cipher to use.
 * @param context Cipher context for encryption operations.
 * @return True if encryption is successful, false otherwise.
 */
bool seal_data ( std::ifstream & in_file, std::ofstream & out_file, EVP_PKEY * public_key,
					const char * symmetric_cipher, EVP_CIPHER_CTX * context )
{
	const EVP_CIPHER * cipher_type = EVP_get_cipherbyname (symmetric_cipher);
	const int symmetric_cipher_n_id = EVP_CIPHER_type (cipher_type);

	const int KEYSIZE = EVP_PKEY_size (public_key), IVSIZE = EVP_CIPHER_iv_length (cipher_type),
			  CIPHERNIDSIZE = 4, KEYLENGTHSIZE = 4, BUFFERSIZE = 8192;

	int key_processed_size = KEYSIZE, in_processed_size = BUFFERSIZE, out_processed_size;
	auto * key = (unsigned char *) malloc (KEYSIZE);
	unsigned char iv[EVP_MAX_IV_LENGTH], in_buffer[BUFFERSIZE], out_buffer[BUFFERSIZE + EVP_MAX_BLOCK_LENGTH];

	if (
		symmetric_cipher_n_id == NID_undef || !key ||
		!EVP_SealInit (context, cipher_type, & key, & key_processed_size, iv, & public_key, 1) ||

	    !write_data (CIPHERNIDSIZE, out_file, (unsigned char *) & symmetric_cipher_n_id) ||
	    !write_data (KEYLENGTHSIZE, out_file, (unsigned char *) & key_processed_size) ||
	    !write_data (KEYSIZE, out_file, key) ||
	    !write_data (IVSIZE, out_file, iv)
	)
	{ if (key) free (key); return false; }

	free (key);

	while (!in_file.eof ())
	{
		if (!read_data (in_processed_size, in_file, in_buffer) ||
		    !EVP_SealUpdate (context, out_buffer, & out_processed_size, in_buffer, in_processed_size) ||
		    !write_data (out_processed_size, out_file, out_buffer))
			return false;
	}

	if (!EVP_SealFinal (context, out_buffer, & out_processed_size) ||
		!write_data (out_processed_size, out_file, out_buffer))
		return false;

	return true;
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * @brief Encrypts (seals) a file using a public key and a symmetric cipher.
 * @param in_filename Name of the input file to encrypt.
 * @param out_filename Name of the output file to write the encrypted data.
 * @param public_key_filename Name of the file containing the public key.
 * @param symmetric_cipher Name of the symmetric cipher to use.
 * @return True if encryption is successful, false otherwise.
 */
bool seal ( const char * in_filename, const char * out_filename, const char * public_key_filename, const char * symmetric_cipher )
{
	if (!in_filename || !out_filename || !public_key_filename || !symmetric_cipher) { if (out_filename) remove (out_filename); return false; }

	ifstream in_file (in_filename, ios::binary); ofstream out_file (out_filename,ios::binary);
	if (in_file.fail () || !(in_file.is_open ()) || out_file.fail () || !(out_file.is_open ())) { remove (out_filename); return false; }

	OpenSSL_add_all_algorithms ();
	FILE * public_key_file = nullptr; EVP_PKEY * public_key = nullptr;
	EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new ();

	bool sealing_successful = (
		context &&
		(public_key_file = fopen (public_key_filename, "r")) &&
		(public_key = PEM_read_PUBKEY (public_key_file, nullptr, nullptr, nullptr)) &&
		seal_data (in_file, out_file, public_key, symmetric_cipher, context)
	);

	if (!sealing_successful) remove (out_filename);

	if (public_key_file) fclose (public_key_file);
	if (public_key) EVP_PKEY_free (public_key);
	if (context) EVP_CIPHER_CTX_free (context);
	in_file.close (); out_file.close ();

	return sealing_successful;
}

// =====================================================================================================================

/**
 * @brief Decrypts (opens) data using a private key.
 * @param in_file Input file stream containing the encrypted data.
 * @param out_file Output file stream to write the decrypted data.
 * @param private_key Private key used for decryption.
 * @param context Cipher context for decryption operations.
 * @return True if decryption is successful, false otherwise.
 */
bool open_data ( std::ifstream & in_file, std::ofstream & out_file, EVP_PKEY * private_key, EVP_CIPHER_CTX * context )
{
	const int CIPHERNIDSIZE = 4, KEYLENGTHSIZE = 4, BUFFERSIZE = 8192;

	const EVP_CIPHER * cipher_type;
	int symmetric_cipher_n_id, key_length, in_processed_size = BUFFERSIZE, out_processed_size;
	unsigned char * key = nullptr;
	unsigned char iv[EVP_MAX_IV_LENGTH], in_buffer[BUFFERSIZE], out_buffer[BUFFERSIZE + EVP_MAX_BLOCK_LENGTH];

	if (
		!in_file.read ((char *) & symmetric_cipher_n_id, CIPHERNIDSIZE) || !(cipher_type = EVP_get_cipherbynid (symmetric_cipher_n_id)) ||
	    !in_file.read ((char *) & key_length, KEYLENGTHSIZE) || key_length <= 0 || !(key = (unsigned char *) malloc (key_length)) ||
		!in_file.read ((char *) key, key_length) ||
		!in_file.read ((char *) iv, EVP_CIPHER_iv_length (cipher_type)) ||

		!EVP_OpenInit (context, cipher_type, key, key_length, iv, private_key)
	)
	{ if (key) free (key); return false; }

	free (key);

	while (!in_file.eof ())
	{
		if (!read_data (in_processed_size, in_file, in_buffer) ||
		    !EVP_OpenUpdate (context, out_buffer, & out_processed_size, in_buffer, in_processed_size) ||
		    !write_data (out_processed_size, out_file, out_buffer))
			return false;
	}

	if (!EVP_OpenFinal (context, out_buffer, & out_processed_size) ||
	    !write_data (out_processed_size, out_file, out_buffer))
		return false;

	return true;
}

// ---------------------------------------------------------------------------------------------------------------------

/**
 * @brief Decrypts (opens) a file using a private key.
 * @param in_filename Name of the input file to decrypt.
 * @param out_filename Name of the output file to write the decrypted data.
 * @param private_key_filename Name of the file containing the private key.
 * @return True if decryption is successful, false otherwise.
 */
bool open ( const char * in_filename, const char * out_filename, const char * private_key_filename )
{
	if (!in_filename || !out_filename || !private_key_filename) { if (out_filename) remove (out_filename); return false; }

	ifstream in_file (in_filename, ios::binary); ofstream out_file (out_filename,ios::binary);
	if (in_file.fail () || !(in_file.is_open ()) || out_file.fail () || !(out_file.is_open ())) { remove (out_filename); return false; }

	OpenSSL_add_all_algorithms ();
	FILE * private_key_file = nullptr; EVP_PKEY * private_key = nullptr;
	EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new ();

	bool opening_successful = (
			context &&
			(private_key_file = fopen (private_key_filename, "r")) &&
			(private_key = PEM_read_PrivateKey (private_key_file, nullptr, nullptr, nullptr)) &&
			open_data (in_file, out_file, private_key, context)
	);

	if (!opening_successful) remove (out_filename);

	if (private_key_file) fclose (private_key_file);
	if (private_key) EVP_PKEY_free (private_key);
	if (context) EVP_CIPHER_CTX_free (context);
	in_file.close (); out_file.close ();

	return opening_successful;
}

// =====================================================================================================================

int main ( )
{
    assert ( seal ("fileToEncrypt", "sealed.bin", "PublicKey.pem", "aes-128-cbc") );
    assert ( open ("sealed.bin", "openedFileToEncrypt", "PrivateKey.pem") );

    assert ( open ("sealed_sample.bin", "opened_sample.txt", "PrivateKey.pem") );

    return 0;
}

