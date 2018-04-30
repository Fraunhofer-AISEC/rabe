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

struct CpAbeContext* rabe_bsw_context_create();
void rabe_bsw_context_destroy(struct CpAbeContext* ctx);
struct CpAbeSecretKey* rabe_bsw_keygen(const struct CpAbeContext* ctx, const char* attributes);
void rabe_bsw_keygen_destroy(void* sk);
int32_t rabe_bsw_encrypt(const void* pk, char* policy, char* pt, int32_t pt_len, char** ct, int32_t *ct_len);
int32_t rabe_bsw_decrypt(const struct CpAbeSecretKey* sk, const char* ct, uint32_t ct_len, char** pt_buf, uint32_t *pt_len);

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
  ctx = rabe_bsw_context_create ();

  /* Keygen */
  struct CpAbeSecretKey* sk = rabe_bsw_keygen (ctx, attributes);

  /* Encrypt */
  assert (0 == rabe_bsw_encrypt (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}",
                                 pt, pt_len,
                                 &ct_buf, &ct_len));
  rabe_bsw_context_destroy(ctx);
  
  /* Decrypt */
  assert (0 == rabe_bsw_decrypt (sk, ct_buf, ct_len, &buf, &pt_len));
  rabe_bsw_keygen_destroy (sk);
  assert (0 == strcmp (buf, pt));
  return 0;
}
