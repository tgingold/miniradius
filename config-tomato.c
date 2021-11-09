#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "bcmnvram.h"

#define MAX_USERS 16
static unsigned nbr_users;
static struct user users[MAX_USERS];

struct user *
get_user(const unsigned char *name, unsigned name_len)
{
  unsigned i;

  for (i = 0; i < nbr_users; i++) {
    unsigned k;
    struct user *u = &users[i];
    if (u->name == NULL)
      return NULL;

    /* Manual string compare. */
    for (k = 0; k < name_len; k++)
      if (name[k] != u->name[k])
	break;
    if (k == name_len && u->name[k] == 0)
      return u;
  }
  return NULL;
}

static int config_cert(SSL_CTX *ctx)
{
  /* Set the key and cert */
  char *cert = nvram_get("miniradiusd_cert");
  size_t len = strlen(cert);

  if (cert == NULL) {
    log_err("no cert defined\n");
    return -1;
  }

  BIO* bio = BIO_new(BIO_s_mem());
  BIO_write(bio, cert, len);
  X509* certX509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!certX509) {
    log_err("unable to parse cert\n");
    return -1;
  }
  if (SSL_CTX_use_certificate(ctx, certX509) <= 0) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  X509_free(certX509);
  return 0;
}

static int config_pkey(SSL_CTX *ctx)
{
  char *pkey = nvram_get("miniradiusd_key");
  size_t len = strlen(pkey);

  if (pkey == NULL) {
    log_err("no key defined\n");
    return -1;
  }

  BIO* bio = BIO_new(BIO_s_mem());
  BIO_write(bio, pkey, len);
  EVP_PKEY *evpkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!evpkey) {
    log_err("unable to parse evpkey\n");
    return -1;
  }
  if (SSL_CTX_use_PrivateKey(ctx, evpkey) <= 0) {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  EVP_PKEY_free(evpkey);

  return 0;
}

int config_ssl(SSL_CTX *ctx)
{
  /* Set the key and cert */
  if (config_cert(ctx) < 0)
    return -1;
  if (config_pkey(ctx) < 0)
    return -1;

  if (SSL_CTX_check_private_key(ctx) <= 0) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

int config_init(int argc, char **argv)
{
  static const char alt_prog[] = "/tmp/miniradiusd";
  char *s;
  char *p;
  char *usr;

  if (strcmp (argv[0], alt_prog) != 0
      && access(alt_prog, X_OK) == 0) {
    /* If there is an exec in /tmp, run it.  */
    log_info("Re-exec %s\n", alt_prog);
    argv[0] = (char *)alt_prog;
    execv(alt_prog, argv);
    return -1;
  }

  nvram_init(NULL);

  /* Check enabled.  */
  s = nvram_get("miniradiusd_en");
  if (s == NULL || s[0] != '1') {
    log_err("miniradiusd not enabled\n");
    return -1;
  }

  /* Radius secret.  */
  s = nvram_get("miniradiusd_secret");
  if (s == NULL || s[0] == 0) {
    log_err("miniradiusd secret not set\n");
    return -1;
  }
  secret = strdup(s);
  secret_len = strlen(secret);

  /* Users.  */
  s = nvram_get("miniradiusd_users");
  if (s == NULL) {
    log_err("no users defined\n");
    return -1;
  }
  usr = strdup(s);
  p = usr;
  nbr_users = 0;
  while (*p) {
    /* Skip spaces */
    while (*p == ' ')
      p++;
    users[nbr_users].name = p;

    /* Skip until ':'.  */
    while (*p != ':') {
      if (!*p)
	return -1;
      p++;
    }
    *p++ = 0;
    users[nbr_users].pass = p;

    while (*p && *p != ' ')
      p++;
    nbr_users++;
    if (!*p)
      break;
    *p++ = 0;
    if (nbr_users == MAX_USERS)
      break;
  }
  log_info("Found %u users\n", nbr_users);

  return 0;
}
