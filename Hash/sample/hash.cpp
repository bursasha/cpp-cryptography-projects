#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------------------------------------------------

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------------------------------------------------

#include <openssl/evp.h>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------------------------------------------------

using namespace std;

// =====================================================================================================================

// Controls hash, if it contains bits count of zeros in a bit representation on the left side (MSB).
/**
 * @brief Controls hash to check if it contains the specified number of leading zeros in a bit representation.
 *
 * @param bits Number of leading zero bits required.
 * @param hash The hash value to be checked.
 * @return int Returns 1 if the hash meets the criteria, 0 otherwise.
 */
int controlHash (int bits, const unsigned char * hash)
{
	for (auto i = 0; i < bits; i++)
		if ((hash[i / 8] >> (7 - (i % 8))) & 1) return 0;

	return 1;
}

// =====================================================================================================================

// Converts input message into the hex format and puts it to the output.
/**
 * @brief Converts input message into hexadecimal format and stores it in the output.
 *
 * @param output Pointer to store the hex output.
 * @param input The binary input message.
 * @param length Length of the binary input.
 * @return int Returns 1 on success, 0 on failure.
 */
int convertToHex (char *& output, const unsigned char * input, size_t length)
{
	auto hex = (char *) malloc ((2 * length) + 1);

	if (!hex) return 0;

	hex[2 * length] = '\0';
	for (size_t i = 0; i < length; i++)
		snprintf(& hex[2 * i], 3, "%02x", input[i]);
	output = hex;

	return 1;
}

// =====================================================================================================================

// Random message creating depending on the random number (iteration of while loop) and its length. Why? It has O(1) complexity in reference to the message length.
/**
 * @brief Creates a random message depending on the random number (iteration of while loop) and its length.
 *
 * @param message Buffer to store the generated message.
 * @param length Length of the message buffer.
 * @param random Iteration number to influence message creation.
 */
void createMessage (unsigned char * message, size_t length, int random)
{
	auto alphas_small = "abcdefghijklmnopqrstuvwxyz", alphas_big = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		nums = "0123456789";

	if (random % 3 == 0) message[random % length] = alphas_small[random % strlen(alphas_small)];
	else if (random % 3 == 1) message[(random * 2) % length] = alphas_big[(random * 2) % strlen(alphas_big)];
	else message[(random * 3) % length] = nums[(random * 3) % strlen(nums)];
}

// =====================================================================================================================

// Depending on the hash function type and zero bits count finds appropriate message which has necessary zero bits count
// from the MSB hash side.
/**
 * @brief Generates a message and computes its hash, ensuring the hash has the specified number of leading zero bits.
 *
 * @param bits Number of leading zero bits required.
 * @param message Pointer to store the generated message in hex format.
 * @param hash Pointer to store the computed hash in hex format.
 * @param type The type of hash function to use (e.g., "sha512").
 * @return int Returns 1 on success, 0 on failure.
 */
int findHashEx (int bits, char ** message, char ** hash, const char * type)
{
	OpenSSL_add_all_digests();
	const EVP_MD * hash_function = EVP_get_digestbyname(type);

	if (!hash_function) return 0;

	size_t hash_length = EVP_MD_size(hash_function);
	unsigned int hash_length_to_check;

	if (bits < 0 || bits > int(8 * hash_length)) return 0; // Hash length = hash bytes count of the used hash function.

	auto hash_tmp = (unsigned char *) malloc (hash_length + 1);

	if (!hash_tmp) return 0;

	hash_tmp[hash_length] = '\0';
	const size_t message_length = 10;
	unsigned char message_tmp[message_length + 1];
	message_tmp[message_length] = '\0';

	auto iteration = 0;
	while (true)
	{
		if (iteration % 50 == 0) // Generates random message.
		{
			if (RAND_bytes(message_tmp, message_length) != 1) continue; // Successful if returns 1.
		}
		else createMessage(message_tmp, message_length, iteration); // Generates random message faster.
		iteration++;

		EVP_MD_CTX * context = EVP_MD_CTX_new();
		if (!context) {
			free(hash_tmp);
			hash_tmp = nullptr;
			return 0;
		}
		if (!EVP_DigestInit_ex(context, hash_function, nullptr)) {
			EVP_MD_CTX_free(context);
			free(hash_tmp);
			hash_tmp = nullptr;
			return 0;
		}
		if (!EVP_DigestUpdate(context, message_tmp, message_length)) {
			EVP_MD_CTX_free(context);
			free(hash_tmp);
			hash_tmp = nullptr;
			return 0;
		}
		if (!EVP_DigestFinal_ex(context, hash_tmp, & hash_length_to_check)) {
			EVP_MD_CTX_free(context);
			free(hash_tmp);
			hash_tmp = nullptr;
			return 0;
		}
		EVP_MD_CTX_free(context);

		if (controlHash(bits, hash_tmp)) break; // Checks if we created appropriate message.
	}
	if (hash_length_to_check != hash_length) {
		free(hash_tmp);
		hash_tmp = nullptr;
		return 0;
	}

	// Converts message and hash to the hexadecimal format.
	if (!convertToHex(* message, message_tmp, message_length)) {
		free(hash_tmp);
		hash_tmp = nullptr;
		return 0;
	}
	if (!convertToHex(* hash, hash_tmp, hash_length)) {
		free(hash_tmp);
		hash_tmp = nullptr;
		return 0;
	}

	free(hash_tmp);
	hash_tmp = nullptr;
	return 1;
}

// =====================================================================================================================

// Uses findHashEx() with "sha512" hash function type.
/**
 * @brief Uses findHashEx() with "sha512" hash function type.
 *
 * @param bits Number of leading zero bits required.
 * @param message Pointer to store the generated message in hex format.
 * @param hash Pointer to store the computed hash in hex format.
 * @return int Returns 1 on success, 0 on failure.
 */
int findHash (int bits, char ** message, char ** hash) {
	return findHashEx (bits, message, hash, "sha512");
}

// =====================================================================================================================

/**
 * @brief Placeholder function to check if a hash meets certain criteria.
 *
 * @param bits Number of leading zero bits required.
 * @param hash The hash value to be checked.
 * @return int Always returns 1 (function not fully implemented).
 */
int checkHash (int bits, const char * hash)
{
//	for (auto i = 0; i < bits; i++) { if ((hash[i / 8] >> (7 - (i % 8))) & 0) return 0; }
	return 1;
}

// =====================================================================================================================

int main (void) {
	char * message, * hash;

	assert(findHash(0, &message, &hash) == 1);
	assert(message && hash && checkHash(0, hash));
	free(message);
	free(hash);

    assert(findHash(1, &message, &hash) == 1);
    assert(message && hash && checkHash(1, hash));
    free(message);
    free(hash);

    assert(findHash(2, &message, &hash) == 1);
    assert(message && hash && checkHash(2, hash));
    free(message);
    free(hash);

    assert(findHash(3, &message, &hash) == 1);
    assert(message && hash && checkHash(3, hash));
    free(message);
    free(hash);

    assert(findHash(-1, &message, &hash) == 0);

	return EXIT_SUCCESS;
}

