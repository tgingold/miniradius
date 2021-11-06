/* Radius shared secret between this server and the clients.  */
extern unsigned char *secret;
extern unsigned secret_len;

struct user {
  const char *name;
  const char *pass;
};

struct user *get_user(const unsigned char *name, unsigned name_len);

int config_init(void);
int config_ssl(SSL_CTX *ctx);
