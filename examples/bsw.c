#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/**
 * TODO: The structs and prototypes need to be refactored into a rabe.h that
 * can be used in C code
 */
struct CpAbeCiphertext;
struct CpAbeContext;
struct CpAbeSecretKey;

struct CpAbeContext* bsw_context_create();
void bsw_context_destroy(struct CpAbeContext* ctx);
struct CpAbeSecretKey* bsw_keygen(const struct CpAbeContext* ctx, const char* attributes);
void bsw_keygen_destroy(void* sk);
struct CpAbeCiphertext* bsw_encrypt(const void* pk, char* policy, char* pt, int32_t pt_len);
int32_t bsw_serialize_size (const struct CpAbeCiphertext* ct);
char* bsw_serialize (const struct CpAbeCiphertext *ct, uint32_t *size);
struct CpAbeCiphertext* bsw_deserialize (const char* buf, uint32_t buf_len);
void bsw_decrypt(const struct CpAbeSecretKey* sk, const struct CpAbeCiphertext* ct, const char* buf);
int32_t bsw_decrypt_get_size (const struct CpAbeCiphertext *ct);

int main () {
  struct CpAbeContext *ctx;
  const char *attributes ="C,B";
  char *ct_buf;
  int32_t ct_len;
  int32_t pt_len;
  char *pt = "Hsddkfdskello =)";
  char *buf;
  pt_len = strlen (pt) + 1;
  
  /* Setup */
  ctx = bsw_context_create ();

  /* Keygen */
  struct CpAbeSecretKey* sk = bsw_keygen (ctx, attributes);

  /* Encrypt */
  struct CpAbeCiphertext *ct = bsw_encrypt (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", pt, pt_len);
  bsw_context_destroy(ctx);
  
  /* Serialize */
  ct_len = bsw_serialize_size (ct);
  ct_buf = bsw_serialize (ct, &ct_len);
  
  /* Deserialize */
  struct CpAbeCiphertext *ct_dup = bsw_deserialize (ct_buf, ct_len);
  free (ct_buf);
  
  /* Decrypt */
  pt_len = bsw_decrypt_get_size (ct_dup);
  buf = malloc (pt_len);
  bsw_decrypt (sk, ct_dup, buf);
  bsw_keygen_destroy (sk);
  assert (0 == strcmp (buf, pt));
  return 0;
}
