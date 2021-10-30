#include <stddef.h>
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

