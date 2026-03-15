#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "RequiredFunctions.c"
/*
 * ============================================================
 * Kerberos KDC / Authentication Server — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or alter their formats.
 *  - The grading scripts depend strictly on these filenames.
 *
 * This program implements the Authentication Service (AS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and temporary keys are assumed to have
 * been generated BEFORE this program runs.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (AS PHASE):
 *
 * 1) Verify the client’s signature on its temporary public key
 * 2) Derive a shared secret using ECDH
 * 3) Derive Key_Client_AS from the shared secret
 * 4) Issue a Ticket Granting Ticket (TGT)
 * 5) Build and encrypt AS_REP.txt
 *
 * Cryptographic concepts involved:
 *  - ECDSA signature verification
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption (ECB for simplicity in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Read and understand them before implementing this file.
 *
 * ============================================================
 */

int main(int argc, char *argv[])
{

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : Client_Signature.txt
	 * argv[2] : Client_temp_PK.txt
	 * argv[3] : AS_temp_SK.txt
	 * argv[4] : AS_temp_PK.txt
	 *
	 * These files MUST already exist.
	 * The KDC must NOT generate any keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: %s <Client_Signature> <Client_temp_PK> <AS_temp_SK> <AS_temp_PK>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_sig_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_sk_path = argv[3];
	const char *as_temp_pk_path = argv[4];

	/* Buffers for cryptographic material */
	//unsigned char key_client_as[32];
	//unsigned char key_client_tgs[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required input files exist
	 *
	 * The AS must ensure:
	 *  - Client signature file exists
	 *  - AS temporary key pair exists
	 *
	 * Abort immediately on missing files.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_sig_path
	 *        as_temp_sk_path
	 *        as_temp_pk_path
	 *  - Print descriptive errors and exit on failure
	 */

	if (!file_exists(client_sig_path)) {
		fprintf(stderr, "KDC: client_sig_path not found\n");
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path)) {
		fprintf(stderr, "KDC: client_temp_pk_path not found\n");
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_pk_path)) {
		fprintf(stderr, "KDC: as_temp_pk_path not found\n");
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_sk_path)) {
		fprintf(stderr, "KDC: as_temp_sk_path not found\n");
		return EXIT_FAILURE;
	}
	/* ------------------------------------------------------------
	 * STEP 1: Verify client identity
	 *
	 * The client authenticates by signing its temporary
	 * public key using its long-term private key.
	 *
	 * Verification inputs:
	 *  - Client_PK.txt        (long-term client public key)
	 *  - Client_temp_PK.txt  (signed data)
	 *  - Client_Signature.txt
	 *
	 * Abort if verification fails.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Verify ECDSA signature
	 *  - Use Client_PK.txt as the verification key
	 *  - Treat failure as an authentication failure
	 */

	if(!file_exists("Client_PK.txt")) {
		fprintf(stderr, "KDC: Client_PK.txt not found\n");
		return EXIT_FAILURE;
	}
	int verify_success = ecdsa_verify_file_from_hex("Client_PK.txt", client_temp_pk_path, client_sig_path);
	if (!verify_success) {
		fprintf(stderr, "KDC: client auth failed [Step1]\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 2: Derive shared secret (ECDH)
	 *
	 * Compute:
	 *
	 *   shared_secret = ECDH(AS_temp_SK, Client_temp_PK)
	 *
	 * The raw shared secret MUST be written to:
	 *      "shared_secret.txt"   (hex format)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the AS temporary private key
	 *  - Use the client's temporary public key
	 *  - Write the shared secret to shared_secret.txt (hex)
	 */

	unsigned char *shared_secret = NULL;
	size_t shared_secret_length = 0;
	int ecdh_shared_secret_success = ecdh_shared_secret_files(as_temp_sk_path, client_temp_pk_path, 
															&shared_secret, &shared_secret_length);

	if(ecdh_shared_secret_success != 1) {
		fprintf(stderr, "KDC: ECDH failure [step2]\n");
		return EXIT_FAILURE;
	}

	int write_SS_success = write_hex_file("shared_secret.txt", shared_secret, shared_secret_length);
	if (write_SS_success != 1){
		fprintf(stderr, "KDC: failed to write shared secret [step2]\n");
		return EXIT_FAILURE;
	}




	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * Compute:
	 *
	 *   Key_Client_AS = SHA256(shared_secret)
	 *
	 * Write the derived key to:
	 *      "Key_Client_AS.txt"   (hex format, 32 bytes)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Hash the shared secret using SHA-256
	 *  - Write exactly 32 bytes to Key_Client_AS.txt
	 */

	unsigned char key_client_AS_bytes[32];
	int hash_success = sha256_bytes(shared_secret, shared_secret_length, key_client_AS_bytes);
	if (!hash_success) {
		fprintf(stderr, "KDC: failed to hash [step3]\n");
		return EXIT_FAILURE;
	}

	int write_KeyClientAs_success = write_hex_file("Key_Client_AS.txt", key_client_AS_bytes, 32);
	if (write_KeyClientAs_success != 1) {
		fprintf(stderr, "KDC: failed to write Key_client_as.txt [step3]\n");
		return EXIT_FAILURE;
	}


	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated session key (Client ↔ TGS)
	 *
	 * For this demo, the KDC does NOT generate a new
	 * Key_Client_TGS_hex. Instead, it reads an existing one:
	 *
	 *      "Key_Client_TGS_hex.txt"
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_TGS_hex.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes in key_client_tgs
	 */

	char *Key_Client_TGS_hex = read_line("Key_Client_TGS.txt",1);
	if (!Key_Client_TGS_hex) {
		fprintf(stderr, "KDC: Failed to read Key_client_TGS_hex\n");
		return EXIT_FAILURE;
	}
	size_t Key_Client_TGS_hex_len = strlen(Key_Client_TGS_hex);

	//if (Key_Client_TGS_hex_len != 64) {
	//	fprintf(stderr, "KDC: key_client_TGS is not 32 bytes [step4]");
	//	return EXIT_FAILURE;
	//}

	unsigned char *Key_Client_TGS_bytes = NULL;
	size_t Key_Client_TGS_bytes_len = 0;

	int hex2byte_conversion_success = hex_to_bytes(Key_Client_TGS_hex, &Key_Client_TGS_bytes, &Key_Client_TGS_bytes_len);
	
	if (hex2byte_conversion_success != 1 || Key_Client_TGS_bytes_len != 32) {
		fprintf(stderr, "KDC: Step 4 failure\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 5: Build the Ticket Granting Ticket (TGT)
	 *
	 * TGT plaintext format:
	 *
	 *      "Client" || Key_Client_TGS_hex
	 *
	 * The TGT is encrypted using the long-term key shared
	 * between the AS and TGS:
	 *
	 *      Key_AS_TGS.txt
	 *
	 * Encryption:
	 *  - AES-256-ECB (for simplicity in this assignment)
	 *
	 * Output:
	 *  - TGT hex string (stored in memory for next step)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_AS_TGS.txt (hex, 32 bytes)
	 *  - Concatenate client ID and Key_Client_TGS_hex hex
	 *  - AES-encrypt under Key_AS_TGS
	 *  - Hex-encode the ciphertext
	 */

	//read Key_AS_TGS.txgt

	/*
	FILE *key_as_tgs_stream = fopen("Key_AS_TGS.txt", "r");
	if (!key_as_tgs_stream) {
		fprintf(stderr, "KDC: Failed to open Key_AS_TGS (Step5)");
		return EXIT_FAILURE;
	}
	unsigned char Key_AS_TGS[65];
	fgets(Key_AS_TGS, sizeof(key_as_tgs_stream), f);
	fclose(key_as_tgs_stream)
	*/

	//read Key_AS_TGS.txt (hex)
	unsigned char *Key_AS_TGS_bytes = NULL;
	size_t Key_AS_TGS_bytes_len;

	int read_KeyAStgs_toBytes_success = 
			read_hex_file_bytes("Key_AS_TGS.txt", &Key_AS_TGS_bytes, &Key_AS_TGS_bytes_len);
	if (!read_KeyAStgs_toBytes_success) {
		fprintf(stderr, "KDC: Failed to read Key_AS_TGS.txt [step5]\n");
		return EXIT_FAILURE;		
	}

	if (Key_AS_TGS_bytes_len != 32) {
		fprintf(stderr, "KDC: Key_AS_TGS must be 32 bytes [step5]\n");
		return EXIT_FAILURE;
	}

	size_t client_len = strlen("Client");
	//size_t Key_Client_TGS_len = strlen(Key_Client_TGS_hex);
	size_t TGT_buffer_len = client_len + Key_Client_TGS_hex_len;

	//concat client || Key_Client_TGS_hex
	unsigned char *TGT_plaintext_buffer = malloc(TGT_buffer_len + 1);
	memcpy(TGT_plaintext_buffer, "Client", client_len);
	memcpy(TGT_plaintext_buffer + client_len, Key_Client_TGS_hex, Key_Client_TGS_hex_len);
	TGT_plaintext_buffer[TGT_buffer_len] = '\0';

	//Encrypt with Key_AS_TGS
	char *TGT_cipher_hex = NULL;
	int aes_encrypt_success = aes256_encrypt_bytes_to_hex_string(
									Key_AS_TGS_bytes,
									TGT_plaintext_buffer,
									TGT_buffer_len,
									&TGT_cipher_hex);

	if (aes_encrypt_success != 1) {
		fprintf(stderr, "KDC: Failed to encrypt TGT [step5]\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 6: Build AS_REP
	 *
	 * AS_REP plaintext format:
	 *
	 *   [ 32 bytes Key_Client_TGS_hex ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Encrypt AS_REP using:
	 *
	 *      Key_Client_AS
	 *
	 * Output file:
	 *      "AS_REP.txt"   (hex ciphertext)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Concatenate raw Key_Client_TGS and TGT hex string
	 *  - AES-256 encrypt using Key_Client_AS
	 *  - Hex-encode ciphertext
	 *  - Write to AS_REP.txt (single line)
	 */
	size_t TGT_cipher_hex_length = strlen(TGT_cipher_hex);
	size_t AS_REP_len = Key_Client_TGS_bytes_len + TGT_cipher_hex_length;
	unsigned char *AS_REP_buffer = malloc(AS_REP_len);
	memcpy(AS_REP_buffer, Key_Client_TGS_bytes, Key_Client_TGS_bytes_len);
	memcpy(AS_REP_buffer + Key_Client_TGS_bytes_len, TGT_cipher_hex, TGT_cipher_hex_length);

	unsigned char *as_rep_cipher_bytes = NULL;
	int as_rep_cipher_len = 0;
	int as_rep_aes_encrypt_success = aes256_ecb_encrypt(
										key_client_AS_bytes,
										AS_REP_buffer,
										(int)AS_REP_len,
										&as_rep_cipher_bytes,
										&as_rep_cipher_len
									);
	
	if(as_rep_aes_encrypt_success != 1) {
		fprintf(stderr, "KDC: Failed to encrypt AS_REP [step6]\n");
		return EXIT_FAILURE;		
	}

	int AS_REP_writeSuccess = write_hex_file("AS_REP.txt", as_rep_cipher_bytes, (size_t)as_rep_cipher_len);

	if(AS_REP_writeSuccess != 1) {
		fprintf(stderr, "KDC: Failed to write AS_REP.txt [step6]\n");
		return EXIT_FAILURE;			
	}
	
	//Cleanup
	free(shared_secret);
	free(Key_Client_TGS_hex);
	free(Key_Client_TGS_bytes);
	free(Key_AS_TGS_bytes);
	free(TGT_plaintext_buffer);
	free(TGT_cipher_hex);
	free(AS_REP_buffer);
	free(as_rep_cipher_bytes);

	
	return EXIT_SUCCESS;
}
