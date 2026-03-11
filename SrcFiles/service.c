#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Service / Application Server — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts rely strictly on filenames
 *    and file contents.
 *
 * This program implements the SERVICE side of a simplified,
 * file-based Kerberos protocol.
 *
 * The service validates an application request (APP_REQ)
 * sent by a client and produces an application response
 * (APP_REP.txt).
 *
 * All long-term keys and session keys are assumed to already
 * exist. The service must NOT generate any keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (SERVICE / APP PHASE):
 *
 * 1) Wait for APP_REQ from the client
 * 2) Decrypt Ticket_App using the TGS–service shared key
 * 3) Extract client identity and Key_Client_App
 * 4) Decrypt and verify the client authenticator
 * 5) Accept or reject the request
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
	 * Command-line arguments:
	 *
	 * argv[1] : APP_REQ.txt
	 * argv[2] : Key_TGS_App.txt
	 *
	 * Both files MUST already exist.
	 * ------------------------------------------------------------
	 */
	if (argc != 3) {
		fprintf(stderr,
		        "Usage: %s <APP_REQ file> <Key_TGS_App file>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *app_req_path     = argv[1];
	const char *key_tgs_app_path = argv[2];

	/* ------------------------------------------------------------
	 * STEP 0: Wait for application request
	 *
	 * If APP_REQ.txt does not exist, print:
	 *
	 *      "Service not requested yet"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	if (!file_exists(app_req_path)) {
		printf("Service not requested yet\n");
		return EXIT_FAILURE;
	}

	printf("Service requested\n");

	/* ------------------------------------------------------------
	 * STEP 1: Load TGS–Service shared key
	 *
	 * Read the long-term key shared between the TGS
	 * and the service:
	 *
	 *      Key_TGS_App.txt
	 *
	 * This key MUST be exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	
	unsigned char *key_tgs_app;
	size_t key_tgs_app_length;
	if (read_hex_file_bytes(key_tgs_app_path, &key_tgs_app, &key_tgs_app_length) == 0) {
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 2: Decrypt Ticket_App
	 *
	 * APP_REQ.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: Auth_Client_App (hex)
	 *
	 * Ticket_App was encrypted by the TGS under Key_TGS_App.
	 *
	 * Decrypted Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * ------------------------------------------------------------
	 */

	char *app_req_text = read_line(app_req_path, 1);
	unsigned char *app_req_bytes;
	size_t app_req_bytes_len;
	hex_to_bytes(app_req_text, &app_req_bytes, &app_req_bytes_len);
	printf("app_req_text: %s\n", app_req_text);
	printf("app_req_bytes: %s\n", app_req_bytes);

	unsigned char *plaintext;
	int plaintext_length;
	aes256_ecb_decrypt(key_tgs_app, app_req_bytes, (int)app_req_bytes_len, &plaintext, &plaintext_length);

	// printf("key_tgs_app: %s\n", key_tgs_app);
	// printf("plaintext: %s\n", plaintext);
	// printf("plaintext_length: %d\n", plaintext_length);
	
	/* ------------------------------------------------------------
	 * STEP 3: Parse client identity and Key_Client_App
	 *
	 * From decrypted Ticket_App plaintext:
	 *  - The LAST 64 characters represent Key_Client_App (hex)
	 *  - Everything before that is clientID_1
	 *
	 * Validate:
	 *  - Key_Client_App is exactly 256 bits
	 * ------------------------------------------------------------
	 */

	 // need to abort on malformed data still
	unsigned char *clientID_1 = malloc(7);
	unsigned char *key_client_app = malloc(64);
	for (int x = 0; x < plaintext_length; x++) {
		if (x < 6) {
			clientID_1[x] = plaintext[x];
		}
		else {
			key_client_app[x-6] = plaintext[x];
		}
	}
	// printf("client_id: %s\n", clientID_1);
	// printf("key_client_app: %s\n", key_client_app);

	unsigned char *key_client_app_bytes;
	size_t key_client_app_bytes_len;
	hex_to_bytes(key_client_app, &key_client_app_bytes, &key_client_app_bytes_len);
	// printf("key_client_app_bytes: %s\n", key_client_app_bytes);
	// printf("key_client_app_bytes_len: %d\n", (int)key_client_app_bytes_len);

	/* ------------------------------------------------------------
	 * STEP 4: Decrypt and verify Auth_Client_App
	 *
	 * Auth_Client_App is found on line 2 of APP_REQ.txt.
	 *
	 * It is encrypted using Key_Client_App and should
	 * decrypt to a client identity string (clientID_2).
	 *
	 * ------------------------------------------------------------
	 */

	char *auth_client_app = read_line(app_req_path, 2);
	unsigned char *auth_client_app_bytes;
	size_t auth_client_app_bytes_len;
	hex_to_bytes(auth_client_app, &auth_client_app_bytes, &auth_client_app_bytes_len);
	// printf("auth_client_app: %s\n", auth_client_app);
	// printf("auth_client_app_bytes: %s\n", auth_client_app_bytes);

	unsigned char *clientID_2;
	int clientID_2_length;
	aes256_ecb_decrypt(key_client_app_bytes, auth_client_app_bytes, (int)auth_client_app_bytes_len, &clientID_2, &clientID_2_length);
	// printf("client_id_2: %s\n", clientID_2);

	/* ------------------------------------------------------------
	 * STEP 5: Validate client identity
	 *
	 * Compare:
	 *
	 *      clientID_1 == clientID_2
	 *
	 * If they match:
	 *  - Accept the request
	 *
	 * Otherwise:
	 *  - Reject the request
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Compare the two client ID strings
	 *  - Treat mismatch as authentication failure
	 */
	if (strcmp(clientID_1, clientID_2) != 0) {
		printf("Authentication failure\n");
		return EXIT_FAILURE;
	}
	
	/* ------------------------------------------------------------
	 * STEP 6: Write APP_REP.txt
	 *
	 * On SUCCESS:
	 *  - Write the string "OK" followed by a newline
	 *    to the file:
	 *
	 *      APP_REP.txt
	 *
	 * No other output is permitted.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Create (or overwrite) APP_REP.txt
	 *  - Write exactly:
	 *        OK\n
	 */
	write_text_lines("APP_REP.txt", "OK", NULL, NULL);

	return EXIT_SUCCESS;
}
