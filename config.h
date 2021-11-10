#include <sys/time.h>

/* Radius shared secret between this server and the clients.  */
extern unsigned char *secret;
extern unsigned secret_len;

struct user {
  const char *name;
  const char *pass;
  time_t timeout;
};

struct user *get_user(const unsigned char *name, unsigned name_len);

int config_init(int argc, char **argv);
int config_ssl(SSL_CTX *ctx);

void log_info(const char *msg, ...);
void log_err(const char *msg, ...);
