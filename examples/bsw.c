#include <stdlib.h>
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
int32_t bsw_encrypt_size (const void* pk, char* policy, char* pt, int32_t pt_len);
void bsw_decrypt(const struct CpAbeSecretKey* sk, const struct CpAbeCiphertext* ct, const char* buf);
int32_t bsw_decrypt_get_size (const struct CpAbeCiphertext *ct);

int main () {
  struct CpAbeContext* ctx = bsw_context_create ();
  const char *attributes ="C,B";
  char *ct_buf;
  int32_t ct_len;
  int32_t pt_len;
  char *pt = "Hsddkfdskello =)";
  char *buf;
  pt_len = strlen (pt) + 1;
  
  struct CpAbeSecretKey* sk = bsw_keygen (ctx, attributes);
  ct_len = bsw_encrypt_size (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", pt, pt_len);
  struct CpAbeCiphertext *ct = bsw_encrypt (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", pt, pt_len);
  bsw_context_destroy(ctx);
  pt_len = bsw_decrypt_get_size (ct);
  buf = malloc (pt_len);
  bsw_decrypt (sk, ct, buf);
  bsw_keygen_destroy (sk);
  assert (0 == strcmp (buf, pt));
  return 0;
}
