#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include "RequiredFunctions.c" // Utility functions: Read_File, Write_File, Convert_to_Hex, SHA256, PRNG, AES-ENCrypt/decrypt, HMAC

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

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 */
	//confirm 3 args are present
	if (argc != 4) {
		fprintf(stderr,
		        "Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
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
	FILE *f;

	f = fopen(client_temp_sk_path, "rb");
	//verify temp client sk exists
	if (!f) {
		fprintf("Temporary Client Private key does not exist: %s\n", client_temp_sk_path);
		exit(EXIT_FAILURE);
	}
	fclose(f);
	
	f = fopen(client_temp_pk_path, "rb");
	//verify temp client PK exists
	if (!f) {
		fprintf("Temporary Client Public key does not exist: %s\n", client_temp_pk_path);
		exit(EXIT_FAILURE);
	}
	fclose(f);
//STEP 1: Sign Client temporary public key
//{
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

	int client_sk_perm_length;
	unsigned char *client_sk_permanent = Read_File("Client_SK.txt", &client_sk_perm_length);

	//sign the temp public key using the clients permanent secret key
	unsigned char *signed_client_temp_pk = ecdsa_sign_file_to_hex(client_sk_permanent, client_temp_pk_path, "Client_Signature.txt")
//}







//STEP 2: Wait for AS response
//{
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
			fprintf(stderr, "Failed to read AS_REP.txt")
			return EXIT_FAILURE
		}
	}
//}






//STEP 3: Derive Key_Client_AS
//{
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
	ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_secret_length);


	size_t shared_secret_hash_length = 0;
	unsigned char *shared_secret_hashed = Hash_SHA256(shared_secret, &shared_secret_hash_length);

	//read the hashed shared secret (generated by AS)
	unsigned char *key_client_as_hex = Read_File("Key_Client_AS.txt", &key_client_as);
	size_t out_len = 0;


	//convert the hashe shared secret to bytes
	unsigned char *key_client_as_bytes;
	hex_to_bytes(key_client_as_hex, &key_client_as_bytes, &out_len);

	//byte-by-byte comparison
	//int byte1, byte2;
	//long position = 0;
	//while(1) {
	//	client_SS = fgetc(shared_secret)
	//	AS_SS = fgetc(key_client_as)

	for (size_t i = 0; i < shared_secret_length && i < out_len; i++) {
		if (shared_secret_hashed[i] != key_client_as_bytes[i]) {
			fpprintf(stderr, "shared secrets do not match!");
		}		
	}
//}





//STEP 4: Decrypt AS_REP
	/*
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the plaintext contains:
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

	//AS_REP.txt plaintext format: 32 bytes for TGS || ASCII hex of TGT
	//it is encrypted in the kdc using key_client_as ---> we will decrypt with the same


	int as_rep_cipher_length;
	unsigned char *asrep_cipher = Read_File("AS_REP.txt", &as_rep_cipher_length);

	int plaintext_length;	
	unsigned char *plaintext = NULL;
	int decrypt_success = aes256_ecb_decrypt(key_client_as_bytes, asrep_cipher, as_rep_cipher_length, &plaintext, &plaintext_length);
	free(asrep_cipher);

	if(!decrypt_success || plaintext_length < 32) {
		fprintf(stderr, "AS_REP decryption: FAILED\n");
		return 1;
	}

	//first 32 bytes into key_client_tgs
	unsigned char key_client_tgs[32];
	memcpy(key_client_tgs, plaintext, 32); //destination, source, bytes
//---> do i need to write client_TGS to a file?

	//copy [32:] bytes into key_client_tgt
	int tgt_length_hex = plaintext_length - 32; //not including the 32byte TGS
	unsigned char *tgt_hex = malloc(tgt_length_hex + 1);

	memcpy(tgt_hex, plaintext + 32, tgt_length_hex); //copy the [32:] bytes
	tgt_hex[tgt_length_hex] = '\0';
	free(plaintext);

	//convert TGT to hex
	//unsigned char *key_client_tgt_hex = bytes_to_hex(key_client_tgt, &key_client_tgt_length);
	





//STEP 5: Create TGS_REQ (only once)
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
		//unsigned char* Auth_Client_TGS = AES(Key_Client_TGS, "Client");
		//size_t auth_client_tgs_length;
		//unsigned char *Auth_client_tgs_hex = bytes_to_hex(Auth_Client_TGS, &auth_client_tgs_length)
		//bytes_to_hex("")

		char *auth_client_tgs_hex = NULL; 
		int success_aes256_encrypt = aes256_encrypt_bytes_to_hex_string(key_client_tgs, (const unsigned char *)"Client", 6, &auth_client_tgs_hex);
		int success_write_to_TGS_REQ = write_text_lines("TGS_REQ.txt", tgt_hex, auth_client_tgs_hex, "Service");
		if (!success_aes256_encrypt != 1 || !success_write_to_TGS_REQ != 1) {
			fprintf(stderr, "failed to create Auth_Client_TGS or TGS_REQ.txt\n");
		}
		free(auth_client_tgs_hex);		
	}
	free(tgt_hex);


	
	/* ------------------------------------------------------------
	 * STEP 6: Wait for TGS response
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
		fprintf(stderr, "TGS_REP does not exist: exiting gracefully\n");
		exit(EXIT_FAILURE);
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

	return EXIT_SUCCESS;
}

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile); //get file size
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size + 1); //messageLength variable from main +1 for null
	fread(output, 1, temp_size, pFile); //freads(output buffer, size of element, how many elements to read, input file)
    output[temp_size] = '\0'; //null terminate after the data of temp_size
	fclose(pFile);

    *fileLen = temp_size;
	return output;
}
/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
  fclose(pFile);
}

/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}
