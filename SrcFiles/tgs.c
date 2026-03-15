#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Ticket Granting Server (TGS) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts depend on strict filenames
 *    and exact file structure.
 *
 * This program implements the Ticket Granting Server (TGS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and all session keys are assumed to
 * already exist on disk. The TGS must NOT generate keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (TGS PHASE):
 *
 * 1) Receive and parse TGS_REQ
 * 2) Decrypt and validate the Ticket Granting Ticket (TGT)
 * 3) Verify the client authenticator
 * 4) Issue a service ticket (Ticket_App)
 * 5) Encrypt and return Key_Client_App
 *
 * Cryptographic primitives used conceptually:
 *  - AES-256 encryption/decryption (ECB mode in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * Command-line arguments (file paths):
	 *
	 * argv[1] : TGS_REQ.txt
	 * argv[2] : Key_AS_TGS.txt
	 * argv[3] : Key_Client_TGS.txt
	 * argv[4] : Key_Client_App.txt
	 * argv[5] : Key_TGS_App.txt
	 *
	 * All files MUST already exist.
	 * The TGS must NOT generate any keys.
	 * ------------------------------------------------------------
	 */
	if (argc != 6) {
		fprintf(stderr,
		        "Usage: %s <TGS_REQ> <Key_AS_TGS> <Key_Client_TGS> <Key_Client_App> <Key_TGS_App>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *tgs_req_path        = argv[1];
	const char *key_as_tgs_path     = argv[2];
	const char *key_client_tgs_path = argv[3];
	const char *key_client_app_path = argv[4];
	const char *key_tgs_app_path    = argv[5];

	/* ------------------------------------------------------------
	 * STEP 0: Wait for TGS request
	 *
	 * If the TGS request file does not yet exist, print:
	 *
	 *      "TGS_REQ not created"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	if (!file_exists(tgs_req_path)) {
		printf("TGS_REQ not created\n");
		return EXIT_FAILURE;
	}

	printf("TGS_REQ received\n");

	/* ------------------------------------------------------------
	 * STEP 1: Read and decrypt the Ticket Granting Ticket (TGT)
	 *
	 * TGS_REQ.txt format:
	 *
	 *   line 1: TGT (hex)
	 *   line 2: Auth_Client_TGS (hex)
	 *   line 3: Service ID (plain text, ignored here)
	 *
	 * The TGT is encrypted under the AS–TGS shared key:
	 *      Key_AS_TGS.txt
	 *
	 * Decrypted TGT plaintext format:
	 *
	 *      clientID || Key_Client_TGS_hex
	 *
	 * ------------------------------------------------------------
	 */
	char *tgs_req_text = read_line(tgs_req_path, 1);
	unsigned char *tgs_req_bytes;
	size_t tgs_req_bytes_len;
	hex_to_bytes(tgs_req_text, &tgs_req_bytes, &tgs_req_bytes_len);
	// printf("tgs_req_text: %s\n", tgs_req_text);
	// printf("tgs_req_bytes: %s\n", tgs_req_bytes);

	unsigned char *key_as_tgs;
	size_t key_as_tgs_length;
	if (read_hex_file_bytes(key_as_tgs_path, &key_as_tgs, &key_as_tgs_length) == 0) {
		return EXIT_FAILURE;
	}
	// printf("key_as_tgs: %s\n", key_as_tgs);

	unsigned char *plaintext;
	int plaintext_length;
	aes256_ecb_decrypt(key_as_tgs, tgs_req_bytes, (int)tgs_req_bytes_len, &plaintext, &plaintext_length);
	// printf("plaintext: %s\n", plaintext);


	/* ------------------------------------------------------------
	 * STEP 2: Parse client identity and Key_Client_TGS
	 *
	 * From decrypted TGT plaintext:
	 *  - The LAST 64 characters represent Key_Client_TGS in hex
	 *  - Everything before that is the client ID
	 *
	 * Validate:
	 *  - Key_Client_TGS is exactly 256 bits
	 * ------------------------------------------------------------
	 */

	unsigned char *clientID = malloc(7);
	unsigned char *key_client_tgs = malloc(65);
	for (int x = 0; x < plaintext_length; x++) {
		if (x < plaintext_length-64) {
			clientID[x] = plaintext[x];
		}
		else {
			key_client_tgs[x-6] = plaintext[x];
		}
	}
	clientID[plaintext_length - 64] = '\0';
	key_client_tgs[64] = '\0';
	// printf("clientID: %s\n", clientID);
	// printf("key_client_tgs: %s\n", key_client_tgs);

	unsigned char *key_client_tgs_bytes;
	size_t key_client_tgs_bytes_len;
	hex_to_bytes(key_client_tgs, &key_client_tgs_bytes, &key_client_tgs_bytes_len);


	/* ------------------------------------------------------------
	 * STEP 3: Verify client authenticator
	 *
	 * Auth_Client_TGS is found on line 2 of TGS_REQ.txt.
	 *
	 * It is encrypted using Key_Client_TGS and should
	 * decrypt to a value identifying the client.
	 *
	 * NOTE:
	 *  - For this demo, successful decryption is sufficient.
	 * ------------------------------------------------------------
	 */
	char *tgs_req_text_2 = read_line(tgs_req_path, 2);
	unsigned char *tgs_req_2_bytes;
	size_t tgs_req_2_bytes_len;
	hex_to_bytes(tgs_req_text_2, &tgs_req_2_bytes, &tgs_req_2_bytes_len);

	unsigned char *client_auth;
	int client_auth_length;
	aes256_ecb_decrypt(key_client_tgs_bytes, tgs_req_2_bytes, (int)tgs_req_2_bytes_len, &client_auth, &client_auth_length);
	// printf("client_auth: %s\n", client_auth);

	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated Key_Client_App
	 *
	 * The TGS does NOT generate a new application session key.
	 * Instead, it reads an existing one from:
	 *
	 *      Key_Client_App.txt
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */

	unsigned char *key_client_app;
	size_t key_client_app_length;
	if (read_hex_file_bytes(key_client_app_path, &key_client_app, &key_client_app_length) == 0) {
		return EXIT_FAILURE;
	}

	if (key_client_app_length != 32) {
		printf("key_client_app_length is not 32 bytes\n");
		return EXIT_FAILURE;
	}

	unsigned char *key_client_app_hex = bytes_to_hex(key_client_app, key_client_app_length);
	// printf("key_client_app_hex: %s\n", key_client_app_hex);

	/* ------------------------------------------------------------
	 * STEP 5: Build and encrypt Ticket_App
	 *
	 * Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * Ticket_App is encrypted under the TGS–App shared key:
	 *
	 *      Key_TGS_App.txt
	 *
	 * ------------------------------------------------------------
	 */
	
	unsigned char *key_tgs_app_bytes;
	size_t key_tgs_app_bytes_len;
	read_hex_file_bytes(key_tgs_app_path, &key_tgs_app_bytes, &key_tgs_app_bytes_len);

	const unsigned char *plaintext_2 = malloc(strlen((char*)clientID) + strlen((char*)key_client_app_hex) + 1);
	strcpy((char*)plaintext_2, (char*)clientID);
    strcat((char*)plaintext_2, (char*)key_client_app_hex);
	// printf("plaintext_2: %s\n", plaintext_2);

	unsigned char *ticket_app;
	int ticket_app_length;
	aes256_ecb_encrypt(key_tgs_app_bytes, plaintext_2, strlen((char*)plaintext_2), &ticket_app, &ticket_app_length);
	// printf("ticket_app_length: %d\n", ticket_app_length);
	// printf("ticket_app: %s\n", ticket_app);


	/* ------------------------------------------------------------
	 * STEP 6: Encrypt Key_Client_App for the client
	 *
	 * Encrypt:
	 *
	 *      Key_Client_App_hex
	 *
	 * using:
	 *
	 *      Key_Client_TGS
	 *
	 * Result:
	 *  - enc_key_client_app (hex)
	 * ------------------------------------------------------------
	 */
	unsigned char *enc_key_client_app;
	int enc_key_client_app_length;
	aes256_ecb_encrypt(key_client_tgs_bytes, key_client_app_hex, strlen(key_client_app_hex), &enc_key_client_app, &enc_key_client_app_length);
	// printf("enc_key_client_app: %s\n", enc_key_client_app);
	// printf("enc_key_client_app_length: %d\n", enc_key_client_app_length);


	/* ------------------------------------------------------------
	 * STEP 7: Write TGS_REP.txt
	 *
	 * Output file format (EXACT):
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: enc_key_client_app hex
	 *
	 * Filename MUST be:
	 *      "TGS_REP.txt"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Write exactly two lines to TGS_REP.txt
	 *  - Preserve order and formatting
	 */
	char *ticket_app_hex = bytes_to_hex(ticket_app, (size_t)ticket_app_length);
	char *enc_key_client_app_hex = bytes_to_hex(enc_key_client_app, (size_t)enc_key_client_app_length);
	write_text_lines("TGS_REP.txt", ticket_app_hex, enc_key_client_app_hex, NULL);

	return EXIT_SUCCESS;
}
