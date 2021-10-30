struct user {
  const char *name;
  const char *pass;
};

struct user *get_user(const unsigned char *name, unsigned name_len);
