#include <stdlib.h>
#include <string.h>

void* bsw_context_create();
void bsw_context_destroy(void* ctx);
void* bsw_keygen(const void* ctx, const char* attributes);
void bsw_keygen_destroy(void* sk);
void* bsw_encrypt(const void* pk, char* policy, char* pt, int32_t pt_len, char* ct, int32_t ct_len);
int32_t bsw_encrypt_size (const void* pk, char* policy, char* pt, int32_t pt_len);
void* bsw_decrypt(const void* sk, const void* ct);

int main () {
  void* ctx = bsw_context_create ();
  const char *attributes ="A,B,C";
  char *ct_buf;
  int32_t ct_len;
  int32_t pt_len;
  char *pt = "hello =)";
  pt_len = strlen (pt);
  
  void* sk = bsw_keygen (ctx, attributes);
  ct_len = bsw_encrypt_size (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", pt, pt_len);
  //void* ct = bsw_encrypt (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", pt, pt_len, ct, ct_len);

  //void* pt_n = bsw_decrypt (sk, ct);
  //bsw_keygen_destroy (sk);
  //bsw_context_destroy (ctx);
  return 1;
}
