#include <stddef.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "users.h"

#define NBR_USERS 2
static struct user users[NBR_USERS] = {
  { "tuser", "tpass" },
  { "user2", "pass2" }
};

struct user *
get_user(const unsigned char *name, unsigned name_len)
{
  unsigned i;

  for (i = 0; i < NBR_USERS; i++) {
    unsigned k;
    struct user *u = &users[i];
    for (k = 0; k < name_len; k++)
      if (name[k] != u->name[k])
	break;
    if (k == name_len && u->name[k] == 0)
      return u;
  }
  return NULL;
}

int config_ssl(SSL_CTX *ctx)
{
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

int config_init(void)
{
  return 0;
}
