#include <stdlib.h>

void* abe_context_create ();
void abe_context_destroy (void* ctx);
void* abe_secret_key_create (const void* ctx, const char* policy);
void abe_secret_key_destroy(void* sk);
int abe_decrypt_native (char* sk, char* ct, char* pt);

int main () {
  void* ctx = abe_context_create ();
  void* sk = abe_secret_key_create (ctx, "{\"OR\": [{\"AND\": [{\"ATT\": \"A\"}, {\"ATT\": \"B\"}]}, {\"AND\": [{\"ATT\": \"C\"}, {\"ATT\": \"D\"}]}]}");
  abe_secret_key_destroy (sk);
  abe_context_destroy (ctx);

  return abe_decrypt_native (NULL, NULL, NULL);
}
