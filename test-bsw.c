#include <stdlib.h>

void* bsw_context_create();
void bsw_context_destroy(void* ctx);
void* bsw_keygen(const void* ctx, const char* attributes);
void bsw_keygen_destroy(void* sk);
void* bsw_encrypt(const void* pk, char* policy, char* pt);

int main () {
  void* ctx = bsw_context_create ();
  const char *attributes[3];
  attributes[0] = "A";
  attributes[1] = "B";
  attributes[2] = "C";
  void* sk = bsw_keygen (ctx, attributes);
  void* ct = bsw_encrypt (ctx, "{\"OR\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}", "hello =)");
  void* pt = bsw_decrypt (sk, ct);
  bsw_keygen_destroy (sk);
  bsw_context_destroy (ctx);
  return pt;
}
