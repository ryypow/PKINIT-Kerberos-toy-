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
 * Kerberos Client (File-Based Demo) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or change their formats.
 *  - The grading scripts rely strictly on these filenames.
 *
 * This program implements the CLIENT SIDE of a simplified
 * Kerberos protocol using files for message passing.
 *
 * The client program is executed multiple times by an
 * external script and must correctly handle different
 * protocol phases depending on which files already exist.
 *
 * ------------------------------------------------------------
 * PROTOCOL PHASES IMPLEMENTED BY THIS CLIENT:
 *
 * 1) AS phase   (Authentication Server)
 * 2) TGS_REQ    (Ticket Granting Service Request)
 * 3) APP_REQ    (Application Server Request)
 *
 * Cryptographic primitives used conceptually:
 *  - ECDSA signatures
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption/decryption
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 */
	//confirm 3 args are present
	if (argc != 4) {
		fprintf(stderr,
		        "Client.c: Usage-- %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path     = argv[3];

	/* Buffers for symmetric keys derived during Kerberos */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required client temporary key files exist
	 *
	 * The client must already possess a temporary EC key pair.
	 * If either file is missing, abort immediately.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */
	if (!file_exists(client_temp_sk_path)) {
		fprintf(stderr, "Client: client_temp_sk_path not found");
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path)) {
		fprintf(stderr, "Client: client_temp_pk_path not found");
		return EXIT_FAILURE;
	}


//STEP 1: Sign Client temporary public key
	/* ------------------------------------------------------------
	 * STEP 1: Sign Client temporary public key
	 *
	 * The client authenticates itself to the AS by signing its
	 * temporary public key using its long-term private key.
	 *
	 * INPUT:
	 *  - Client_SK.txt          (long-term client private key)
	 *  - client_temp_pk_path    (temporary public key)
	 *
	 * OUTPUT (must always be regenerated):
	 *  - Client_Signature.txt   (hex-encoded ECDSA signature)
	 *
	 * NOTE:
	 *  - Even if the file already exists, regenerate it.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */

	//sign the temp public key using the clients permanent secret key
	int ecdsasign_success = ecdsa_sign_file_to_hex("Client_SK.txt", client_temp_pk_path, "Client_Signature.txt");
	if(!ecdsasign_success) {
		fprintf(stderr, "Client.c: failed to sign Client_temp_PK.txt [step 1]\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 2: Wait for AS response
	 *
	 * The Authentication Server writes AS_REP.txt when ready.
	 * If it does not yet exist, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check if "AS_REP.txt" exists
	 *  - If not, print a status message and exit SUCCESSFULLY
	 */

// --- TODO: may need to adjust sleep
	int AS_patience = 0;
	while(!file_exists("AS_REP.txt")) {
		usleep(100000); //starting with 100ms
		AS_patience++;
		if (AS_patience > 4) {
			fprintf(stderr, "Client.c: Failed to read AS_REP.txt [step 2]");
			return EXIT_SUCCESS;
		}
	}

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * The client derives a shared secret with the AS using ECDH:
	 *
	 *      shared = ECDH(Client_temp_SK, AS_temp_PK)
	 *
	 * Then derives a symmetric key:
	 *
	 *      Key_Client_AS = SHA256(shared)
	 *
	 * This key MUST match the reference key stored in:
	 *      "Key_Client_AS.txt"
	 *
	 * Abort if the derived key does not match.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */

	unsigned char *shared_secret = NULL;
	size_t shared_secret_length = 0;
	int client_ecdh_success = ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_secret_length);
	if(client_ecdh_success != 1) {
			fprintf(stderr, "Client.c: ecdh_shared_secret_files() failed [step 3]");
			return EXIT_FAILURE;
	}

	unsigned char *Key_Client_AS[32]; //Need to allocate memory, since sha256_bytes() does not
	size_t Key_Client_AS_hash_len = 0; 
	int client_ss_hash_success = sha256_bytes(shared_secret, &Key_Client_AS_hash_len, &Key_Client_AS);

	if (client_ss_hash_success != 1) {
		fprintf(stderr, "Client.c: Failed to hash sharedsecret [step 3]");
		return EXIT_FAILURE;		
	}

	unsigned char *Key_Client_AS_bytes = NULL;
	size_t Key_Client_AS_bytes_len = 0;
	int read_KeyClientAS_success = read_hex_file_bytes("Key_Client_AS.txt", &Key_Client_AS_bytes, &Key_Client_AS_bytes_len);

	if (read_KeyClientAS_success != 1) {
		fprintf(stderr, "Client.c: Failed to read Key_Client_AS.txt [step 3]");
		return EXIT_FAILURE;		
	}

	//byte-by-byte comparison
	//int byte1, byte2;
	//long position = 0;
	//while(1) {
	//	client_SS = fgetc(shared_secret)
	//	AS_SS = fgetc(key_client_as)

	for (size_t i = 0; i < Key_Client_AS_hash_len; i++) {
		if (Key_Client_AS[i] != Key_Client_AS_bytes[i]) {
			fpprintf(stderr, "Client.c: Symmetric keys do not match!");
			return EXIT_FAILURE;	
		}		
	}

//STEP 4: Decrypt AS_REP
	/*
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the AS_REP_plaintext contains:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Extract BOTH values.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */

	//AS_REP.txt AS_REP_plaintext format: 32 bytes for TGS || ASCII hex of TGT
	//it is encrypted in the kdc using key_client_as ---> we will decrypt with the same

	unsigned char *AS_REP_bytes = NULL;
	int AS_REP_bytes_len = 0;
	int read_ASREP_success = read_hex_file_bytes("AS_REP.txt", &AS_REP_bytes, &AS_REP_bytes_len);

	if (read_ASREP_success != 1) {
		fprintf(stderr, "Client.c: Failed to read AS_REP.txt [step 4]");
		return EXIT_FAILURE;		
	}

	int AS_REP_plaintext_len = 0;	
	unsigned char *AS_REP_plaintext = NULL;
	int decrypt_ASREP_success = aes256_decrypt(
								Key_Client_AS_bytes, 
								AS_REP_bytes, 
								AS_REP_bytes_len, 
								&AS_REP_plaintext, 
								&AS_REP_plaintext_len);

	if(decrypt_ASREP_success != 1) {
		fprintf(stderr, "Client.c: AS_REP decryption FAILED\n [step 4]");
		free(AS_REP_bytes);
		free(AS_REP_plaintext);
		return EXIT_FAILURE;
	}

	if(AS_REP_plaintext_len < 32) {
		fprintf(stderr, "Client.c: AS_REP_plaintext is less than 32 bytes [step 4]");
		free(AS_REP_bytes);
		free(AS_REP_plaintext);
		return EXIT_FAILURE;
	}

	//first 32 bytes into key_client_tgs
	unsigned char key_client_tgs[32];
	memcpy(key_client_tgs, AS_REP_plaintext, 32);

	//copy [32:] bytes into key_client_tgt
	size_t TGT_hex_len = AS_REP_plaintext_len - 32; //not including the 32byte TGS
	char *TGT_hex = malloc(TGT_hex_len + 1);

	memcpy(TGT_hex, AS_REP_plaintext + 32, TGT_hex_len); //copy the [32:] bytes
	TGT_hex[TGT_hex_len] = '\0';

	free(AS_REP_plaintext);

//STEP 5: Create TGS_REQ (only once)
{
	/* ------------------------------------------------------------
	 * STEP 5: Create TGS_REQ (only once)
	 *
	 * If TGS_REQ.txt does NOT already exist:
	 *
	 *   Auth_Client_TGS = AES(Key_Client_TGS, "Client")
	 *
	 * Write TGS_REQ.txt with EXACTLY THREE lines:
	 *
	 *   line 1: TGT hex
	 *   line 2: Auth_Client_TGS hex
	 *   line 3: Service ID string (plain text): "Service"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */

	if (!file_exists("TGS_REQ.txt")) { 
		char *Auth_Client_TGS_hex = NULL;
		size_t plaintext_len = strlen("Client");
		int success_aes256_encrypt = aes256_encrypt_bytes_to_hex_string(
										key_client_tgs,
										(const unsigned char *)"Client",
										plaintext_len,
										&Auth_Client_TGS_hex);
		if (!success_aes256_encrypt != 1) {
			fprintf(stderr, "Client.c: failed to encrypt Auth_Client_TGS [step 5]\n");
			return EXIT_FAILURE;
		}
		int success_write_to_TGS_REQ = write_text_lines("TGS_REQ.txt", TGT_hex, Auth_Client_TGS_hex, "Service");
		if (!success_aes256_encrypt != 1 || !success_write_to_TGS_REQ != 1) {
			fprintf(stderr, "Client.c: failed to create TGS_REQ.txt [step 5]\n");
			return EXIT_FAILURE;
		}
		free(Auth_Client_TGS_hex);		
	}
	free(TGT_hex);
}

	
//STEP 6: Wait for TGS response
{
		/* ------------------------------------------------------------
	 *
	 * TGS writes "TGS_REP.txt" when ready.
	 * If missing, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REP.txt"
	 *  - If not present, print status and exit SUCCESSFULLY
	 */

	if (!file_exists("TGS_REP.txt")) {
		fprintf(stderr, "TGS_REP does not exist: exiting gracefully [step 6]\n");
		exit(EXIT_SUCCESS);
	}
}

	/* ------------------------------------------------------------
	 * STEP 7: Recover Key_Client_App
	 *
	 * TGS_REP.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: enc_key_client_app (hex, AES under Key_Client_TGS)
	 *
	 * Decrypt line 2 using Key_Client_TGS to recover:
	 *      Key_Client_App (hex → 32 bytes)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read second line of TGS_REP.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Convert hex string to raw bytes
	 *  - Store exactly 32 bytes in key_client_app
	 */

	unsigned char* second_line_TGS = read_line("TGS_REP.txt", 2); //(hex, AES key_client_tgs)


	unsigned char *Key_Client_App = NULL; //bytes
	int Key_Client_App_length;
	int aes_decrypt_success_tgs = aes256_decrypt_hex_string_to_bytes(key_client_tgs, second_line_TGS, &Key_Client_App, &Key_Client_App_length);
	
	if(aes_decrypt_success_tgs != 1) {
		fprintf(stderr, "Client.c: failed to decrypt TGS_REP.txt [step 7]");
	}
	
	if(Key_Client_App_length != 32) {
		fprintf(stderr, "Client.c: Key_Client_app is not 32 bytes");
		return EXIT_FAILURE;
	}
	/* ------------------------------------------------------------
	 * STEP 8: Create APP_REQ
	 *
	 *   Auth_Client_App = AES(Key_Client_App, "Client")
	 *
	 * Write APP_REQ.txt with EXACTLY TWO lines:
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: Auth_Client_App hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */

	size_t Auth_Client_App_len;
	char *Auth_Client_App = NULL;
	int app_req_encrypt_success = aes256_encrypt_bytes_to_hex_string(
									Key_Client_App,
									(const unsigned char *)"Client",
									Auth_Client_App_len,
									&Auth_Client_App
									);
	
	if (app_req_encrypt_success != 1) {
		fprintf(stderr, "client.c: Failed to encrypt APP_REQ");
		return EXIT_FAILURE;
	}

	unsigned char* Ticket_App = read_line("TGS_REP.txt", 1);

	write_text_lines("APP_REQ.txt", Ticket_App, auth_client_app);

	return EXIT_SUCCESS;
}
