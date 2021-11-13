#include <string.h>

#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/des.h>

#include "mschapv2.h"
#include "dump.h"

#ifdef OPENSSL_NO_MD4
#include "md4.h"
#include "md4.c"
#endif

static void
des_encrypt(const unsigned char clear[8], const unsigned char *key,
	    unsigned char res[8])
{
  unsigned char key64[8];
  DES_key_schedule sched;

  key64[0] = key[0];
  key64[1] = (key[0] << 7) | (key[1] >> 1);
  key64[2] = (key[1] << 6) | (key[2] >> 2);
  key64[3] = (key[2] << 5) | (key[3] >> 3);
  key64[4] = (key[3] << 4) | (key[4] >> 4);
  key64[5] = (key[4] << 3) | (key[5] >> 5);
  key64[6] = (key[5] << 2) | (key[6] >> 6);
  key64[7] = (key[6] << 1);

  DES_set_odd_parity(&key64);
  DES_set_key_unchecked(&key64, &sched);

  DES_ecb_encrypt((DES_cblock *)clear, (DES_cblock *)res, &sched, DES_ENCRYPT);
}

int
mschapv2_ntresp (const unsigned char *challenge,
		 const unsigned char *peer_challenge,
		 const char *user_name,
		 const char *user_pass,
		 const unsigned char *expected_nt_resp,
		 unsigned char *auth_resp)
{
  static const unsigned char magic1[39] =
    {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
     0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
     0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
     0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
  static const unsigned char magic2[41] =
    {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
     0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
     0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
     0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
     0x6E};

  SHA_CTX sha_ctx;
  unsigned char chall_digest[20]; /* Only the first 8 bytes are used */
  unsigned char digest[20];
  MD4_CTX md4_ctx;
  unsigned char pw_hash[21]; /* 16 bytes, zero-extended */
  unsigned char pw_hash_hash[16];
  unsigned char nt_resp[24];
  unsigned char unc[2];
  const char *u;

  if (0) {
    dump_log ("ms-chap-v2 challenge:\n");
    dump_hex (" ", challenge, 16);
    dump_log ("ms-chap-v2 peer-challenge:\n");
    dump_hex (" ", peer_challenge, 16);
  }

  /* RFC 2759 section 8. Pseudocode */
  /* GenerateNTResponse */

  /* ChallengeHash */
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, peer_challenge, 16);  /* Peer challenge */
  SHA1_Update(&sha_ctx, challenge, 16); /* Auth challenge */
  SHA1_Update(&sha_ctx, user_name, strlen(user_name));
  SHA1_Final(chall_digest, &sha_ctx);

  /* NtPasswordHash (password is in unicode) */
  unc[1] = 0;
  MD4_Init(&md4_ctx);
  for (u = user_pass; *u; u++) {
    unc[0] = *u;
    MD4_Update(&md4_ctx, unc, 2);
  }
  MD4_Final(pw_hash, &md4_ctx);

  /* ChallengeResponse */
  memset(pw_hash + 16, 0, 5);
  des_encrypt(chall_digest, pw_hash + 0, nt_resp + 0);
  des_encrypt(chall_digest, pw_hash + 7, nt_resp + 8);
  des_encrypt(chall_digest, pw_hash + 14, nt_resp + 16);

  if (0) {
    dump_log ("ms-chap-v2 computed NTresponse:\n");
    dump_hex (" ", nt_resp, 24);
    dump_log ("ms-chap-v2 expected NTresponse:\n");
    dump_hex (" ", expected_nt_resp, 24);
  }

  if (memcmp(nt_resp, expected_nt_resp, 24) != 0) {
    memset (auth_resp, 0, 20);
    return -1;
  }

  /* Compute auth-string */
  /* HashNtPasswordHash */
  MD4_Init(&md4_ctx);
  MD4_Update(&md4_ctx, pw_hash, 16);
  MD4_Final(pw_hash_hash, &md4_ctx);

  /* ... */
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, pw_hash_hash, 16);
  SHA1_Update(&sha_ctx, nt_resp, 24);
  SHA1_Update(&sha_ctx, magic1, 39);
  SHA1_Final(digest, &sha_ctx);

  /* ... */
  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, digest, 20);
  SHA1_Update(&sha_ctx, chall_digest, 8);
  SHA1_Update(&sha_ctx, magic2, 41);
  SHA1_Final(auth_resp, &sha_ctx);

  return 0;
}
