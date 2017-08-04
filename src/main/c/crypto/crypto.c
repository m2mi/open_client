/*
 * (C) Copyright ${year} Machine-to-Machine Intelligence (M2Mi) Corporation, all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Julien Niset
 */

 #include "crypto.h"

char * sha256_hash_file(const char * file) {

  FILE * fd = NULL;
  EVP_MD_CTX * mdctx = NULL;
  unsigned char * buffer = NULL;
  unsigned char * digest = NULL;
  unsigned int digest_len = 0;

   fd = fopen(file, "r");
   if(fd == NULL) {
     error("Failed to open file %s.", file);
 		 goto done;
   }

   mdctx = EVP_MD_CTX_create();
   if(mdctx == NULL) {
     error("Failed to create hashing context.");
 		 goto done;
   }
   if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
     error("Failed to init hashing context.");
 		 goto done;
   }

   const int bufSize = 4096;
   buffer = malloc(bufSize);
   if(buffer == NULL) {
     error("Failed to malloc space for reading buffer.");
 		 goto done;
   }
   int bytesRead = 0;
   while((bytesRead = fread(buffer, 1, bufSize, fd)) > 0) {
      if(1 != EVP_DigestUpdate(mdctx, buffer, bytesRead)) {
        error("Failed to update digest.");
    	goto done;
      }
   }

   digest_len = EVP_MD_size(EVP_sha256());
   digest = (unsigned char *)OPENSSL_malloc(digest_len + 1);

   if(digest == NULL) {
     error("Failed to allocate space for digest.");
     goto done;
   }

   if(1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
     error("Failed to finalize digest.");
     goto done;
   }

   digest[digest_len] = 0;

   done: {
     EVP_MD_CTX_destroy(mdctx);
     free(buffer);
     fclose(fd);
   }

   char * b64 = to_base64((char *)digest, digest_len);
   free(digest);
   return b64;

 }

char * rsa_sha256_sign_file(RSA * privKey, const char * file) {

   unsigned char * output = NULL;
   size_t output_len = 0;
   FILE * fd = NULL;
   EVP_MD_CTX * ctx = NULL;
   EVP_PKEY_CTX * pkey_ctx = NULL;
   unsigned char * buffer = NULL;

   fd = fopen(file, "r");
   if(fd == NULL) {
     error("Failed to open file %s.", file);
 		 goto done;
   }

   // setup RSA key with context
   EVP_PKEY * pkey = EVP_PKEY_new();
   if(EVP_PKEY_assign_RSA(pkey, privKey) != 1) {
     error("Failed to assign signing key.");
     goto done;
   }
   pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
   EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);

   // setup digest with context
   ctx = EVP_MD_CTX_create();
   if(ctx == NULL) {
       error("Failed to create context");
       goto done;
   }

   const EVP_MD * md = EVP_get_digestbyname("SHA256");
   if(md == NULL) {
       error("Failed to get digest");
       goto done;
   }

   if(EVP_DigestSignInit(ctx, &pkey_ctx, md, NULL, pkey) != 1) {
       error("Failed to init signing digest");
       goto done;
   }

   const int bufSize = 4096;
   buffer = malloc(bufSize);
   if(buffer == NULL) {
     error("Failed to malloc buffer to read file.");
     goto done;
   }
   size_t bRead = 0;
   while((bRead = fread(buffer, 1, bufSize, fd)) > 0) { // Attention ici, verifier que c'est buffer et bufSize
    debug("read %zu bytes\n", bRead);
     if(EVP_DigestSignUpdate(ctx, buffer, bRead) != 1) {
         error("Failed to update digest.");
         goto done;
     }
   }

   size_t req = 0;
   if(EVP_DigestSignFinal(ctx, NULL, &req) != 1) {
       error("Failed to sign digest (1).");
       goto done;
   }

   if(!(req > 0)) {
       error("Failed to sign digest (2).");
       goto done;
   }

   output = OPENSSL_malloc(req + 1);
   if(output == NULL) {
       error("Failed to malloc output.");
       goto done;
   }

   output_len = req;
   if(EVP_DigestSignFinal(ctx, output, &output_len) != 1) {
       error("Failed to sign digest (3).");
       goto done;
   }
   output[output_len] = '\0';

   done: {
        EVP_MD_CTX_destroy(ctx);
        fclose(fd);
        free(buffer);
   }

    char * b64 = to_base64((char *)output, output_len);
    free(output);
    return b64;
 }

RSA * load_rsa_private_key(const char * priv_key_file) {

   FILE * priv_file = fopen(priv_key_file, "r");
   if(priv_file == NULL) {
     error("Failed to open private key file.");
      return NULL;
   }
   RSA * privKey = RSA_new();
   if (!PEM_read_RSAPrivateKey(priv_file, &privKey, NULL, NULL)) { // Add password in futute
     error("Failed to load private key.");
     return NULL;
   }

   return privKey;
 }

 char * to_base64(const char * input, size_t size) {

   if(input == NULL)
      return NULL;

   char * output;

   BIO *b64, *bio;
   BUF_MEM *bio_ptr;

   b64 = BIO_new(BIO_f_base64());
   bio = BIO_new(BIO_s_mem());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   BIO_push(b64, bio);
   BIO_write(b64, input, size);
   BIO_flush(b64);
   BIO_get_mem_ptr(bio, &bio_ptr);
   BIO_set_close(bio, BIO_NOCLOSE);
   BIO_free_all(b64);

   output = calloc(bio_ptr->length + 1, sizeof(char));
   if(output == NULL) {
     error("Failed to malloc output buffer.");
     return NULL;
   }

   snprintf(output, bio_ptr->length + 1, "%s", bio_ptr->data);

   return output;

 }
