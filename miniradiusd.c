/* miniradius - a minimal radius server for WPA
   Copyright (C) 2021 Tristan Gingold

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/des.h>

#include "hmac_md5.h"
#include "mschapv2.h"
#include "radius.h"
#include "config.h"
#include "dump.h"

/* If True, dump packets on stdout.  */
static unsigned flag_dump = 0;

/* UDP port for the server.  */
unsigned port = 1812;

/* Radius shared secret between this server and the clients.  */
unsigned char *secret;
unsigned secret_len;

static SSL_CTX *ssl_ctxt;

#define BUF_LEN 4096
#define MTU 1024

struct udp_pkt {
  unsigned fd;
  time_t cur_time;
  struct sockaddr_in caddr;

  unsigned char req[BUF_LEN];
  unsigned char rep[BUF_LEN];
  unsigned reqlen;
  unsigned replen;
};

struct eap_ctxt {
  struct sockaddr peer_addr;
  time_t last_time;
  uint16_t mtu;
  uint8_t rad_id;

  /* Timeouts */

  /* Radius-State */
  unsigned char radius_state[4];

  /* State */
  enum eap_state {
    S_FREE,
    S_INIT,
    S_HANDSHAKE,
    S_TUN_SEND_IDENTITY,
    S_TUN_RECV_IDENTITY,
    S_TUN_RECV_CHALLENGE,
    S_TUN_RECV_RESULT
  } state;

  /* TLS encapsulation
     - buffer
     - length

     Input and Output BIOs.
  */
  uint32_t total_len;
  uint32_t last_len;
  uint32_t cur_len;
  uint8_t last_id;
  uint8_t rx_tx;

  /* Input and Output BIOs for encapsulation.  */
  BIO *mem_rd;  /* Data read from client.  */
  BIO *mem_wr;  /* Data to be sent to client.  */
  SSL *ssl;

  /* Protocol for authorization: md5-challenge, ms-chap-v2.  */
  unsigned char proto_auth;

  unsigned char challenge[16];
  unsigned char auth_string[20];  /* For ms-chap-v2 */
  unsigned char success;
  struct user *user;
};

/* Number of seconds from the last received packet.  */
#define CTXT_TIMEOUT 10

#define NBR_EAP_CTXTS 8
static struct eap_ctxt eap_ctxts[NBR_EAP_CTXTS];

static uint16_t
read16 (const unsigned char *p)
{
  return (p[0] << 8) | p[1];
}

static uint32_t
read32 (const unsigned char *p)
{
  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static void
write16 (unsigned char *p, uint16_t v)
{
  p[0] = v >> 8;
  p[1] = v >> 0;
}

static void
write32 (unsigned char *p, uint32_t v)
{
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v >> 0;
}

/* Encode a string according to ms-chap-v2 */
static void
write_hex(unsigned char *p, const unsigned char *s, unsigned len)
{
  static const unsigned char hex[] = "0123456789ABCDEF";
  unsigned i;
  unsigned c;

  for (i = 0; i < len; i++) {
    c = s[i];
    *p++ = hex[(c >> 4) & 0x0f];
    *p++ = hex[(c >> 0) & 0x0f];
  }
}

/* Check authenticator attribute.
   Return 1 if OK, -1 if error, 0 if not present.  */
static int
auth_request(unsigned char *p, unsigned plen)
{
  unsigned off;

  /* Authentify.  */
  for (off = 20; off < plen; ) {
    unsigned attr = p[off];

    if (attr == ATTR_MESSAGE_AUTHENTICATOR
	&& p[off + 1] == 18) {
      /* Do HMAC-MD5 in place.  */
      unsigned char digest[16];
      unsigned char computed_digest[16];
      memcpy (digest, p + off + 2, 16);
      memset (p + off + 2, 0, 16);

      hmac_md5(p, plen, secret, secret_len, computed_digest);
      memcpy (p + off + 2, digest, 16);
      if (memcmp(computed_digest, digest, 16) != 0)
	return -1;
      else
	return 1;
    }

    off += p[off + 1];
  }
  return 0;
}

/* Compute authenticator attribute (and write to P_MAC) and authenticator
   field.  */
static unsigned int
compute_eap_authenticator_noalloc (unsigned char *rep, unsigned int len,
				   unsigned char *p_mac)
{
  MD5_CTX md5_ctxt;

  /* RADIUS packet length.  */
  rep[3] = len & 0xff;
  rep[2] = len >> 8;

  /* Compute hmac for Message-Authenticator.
     From RFC 3579, 3.2 Message-Authenticator:

     For Access-Challenge, Access-Accept, and Access-Reject packets,
     the Message-Authenticator is calculated as follows, using the
     Request-Authenticator from the Access-Request this packet is in
     reply to:

     Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
               Request Authenticator, Attributes)

     When the message integrity check is calculated the signature
     string should be considered to be sixteen octets of zero.  The
     shared secret is used as the key for the HMAC-MD5 message
     integrity check.  The Message-Authenticator is calculated and
     inserted in the packet before the Response Authenticator is
     calculated.  */
  hmac_md5(rep, len, secret, secret_len, p_mac);

  /* Compute Authenticator.
     From RFC 2865, 3 Packet Format

     The value of the Authenticator field in Access-Accept, Access-
     Reject, and Access-Challenge packets is called the Response
     Authenticator, and contains a one-way MD5 hash calculated over
     a stream of octets consisting of: the RADIUS packet, beginning
     with the Code field, including the Identifier, the Length, the
     Request Authenticator field from the Access-Request packet, and
     the response Attributes, followed by the shared secret.  That is,

     ResponseAuth =  MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
       where + denotes concatenation.  */
  MD5_Init (&md5_ctxt);
  MD5_Update (&md5_ctxt, rep, len);
  MD5_Update (&md5_ctxt, secret, secret_len);
  MD5_Final (rep + 4, &md5_ctxt);

  return len;
}

static unsigned int
compute_eap_authenticator (unsigned char *rep, unsigned int len)
{
  unsigned char *r = rep + len;
  unsigned char *p_mac;

  /* Message authenticator.  */
  r[0] = ATTR_MESSAGE_AUTHENTICATOR;
  r[1] = 18;
  p_mac = r + 2;
  memset (p_mac, 0, 16);
  r += r[1];

  return compute_eap_authenticator_noalloc(rep, r - rep, p_mac);
}

static void
app_radius_hdr (unsigned char *rep, unsigned *off,
		unsigned char code, unsigned char id,
		const unsigned char *reqauth)
{
  /* Header.  */
  rep[0] = code;
  rep[1] = id;
  rep[2] = 0;
  rep[3] = 0;

  /* Authenticator: copy RequestAuth.  */
  memcpy(rep + 4, reqauth, 16);

  *off = 20;
}

static void
app_radius_attr(unsigned char *rep, unsigned *off,
		unsigned char code, const unsigned char *buf, unsigned len)
{
  unsigned l = *off;
  assert(l + len < BUF_LEN);
  assert(len <= 253);
  rep[l++] = code;
  rep[l++] = len + 2;
  memcpy(rep + l, buf, len);
  *off = l + len;
}

static void
app_radius_eap(unsigned char *rep, unsigned *off,
	       unsigned char *buf, unsigned len)
{
  buf[2] = len >> 8;
  buf[3] = len & 0x0f;

  while (len > 0) {
    unsigned l = len > 253 ? 253 : len;
    app_radius_attr(rep, off, ATTR_EAP_MESSAGE, buf, l);
    len -= l;
    buf += l;
  }
}

static void
app_radius_peap(unsigned char *rep, unsigned *off,
		unsigned char *hdr, unsigned hlen,
		const unsigned char *buf, unsigned len)
{
  hdr[2] = (hlen + len) >> 8;
  hdr[3] = (hlen + len) >> 0;

  /* TODO: concat.  */
  app_radius_attr(rep, off, ATTR_EAP_MESSAGE, hdr, hlen);

  while (len > 0) {
    unsigned l = len > 253 ? 253 : len;
    app_radius_attr(rep, off, ATTR_EAP_MESSAGE, buf, l);
    len -= l;
    buf += l;
  }
}

/* Handle the first EAP packet.  */
static int
do_eap_init(struct udp_pkt *pkt,
	    unsigned char *req, unsigned reqlen)
{
  struct eap_ctxt *ctxt;
  unsigned char rsp[6];
  unsigned off;
  unsigned i;

  /* Find a free context.  Linear. */
  ctxt = NULL;
  for (i = 0; i < NBR_EAP_CTXTS; i++) {
    ctxt = &eap_ctxts[i];
    if (ctxt->last_time + CTXT_TIMEOUT <= pkt->cur_time) {
      /* Can free the context.  */
      SSL_free (ctxt->ssl);
      memset (ctxt, 0, sizeof *ctxt);
    }
    if (ctxt->state == S_FREE) {
      ctxt->state = S_INIT;
      ctxt->radius_state[0] = i;
      break;
    }
    ctxt = NULL;
  }
  if (ctxt == NULL) {
    log_err ("No EAP context available\n");
    return -1;
  }

  /* Fill the context. */
  memcpy (&ctxt->peer_addr, &pkt->caddr, sizeof pkt->caddr);
  ctxt->rad_id = pkt->req[1];
  ctxt->last_id = req[1] + 1;
  ctxt->last_time = pkt->cur_time;

  /* Default: use md5-challenge. */
  ctxt->proto_auth = EAP_TYPE_MD5_CHALLENGE;
  //ctxt->proto_auth = EAP_TYPE_MS_CHAP_V2;

  /* Prepare the response: start TLS.  */
  app_radius_hdr(pkt->rep, &off,
		 CODE_ACCESS_CHALLENGE, ctxt->rad_id, pkt->req + 4);

  rsp[0] = EAP_CODE_REQUEST;
  rsp[1] = ctxt->last_id;  /* id */
  rsp[2] = 0;       /* len */
  rsp[3] = 0;
  rsp[4] = EAP_TYPE_PEAP; // EAP_TTLS;
  rsp[5] = PEAP_FLAG_START;
  app_radius_eap(pkt->rep, &off, rsp, 6);

  app_radius_attr(pkt->rep, &off,
		  ATTR_STATE, ctxt->radius_state, sizeof ctxt->radius_state);

  return compute_eap_authenticator(pkt->rep, off);
}

/* RFC 2548 p21-22 */
static void
mppe_encrypt (const unsigned char *salt,
	      const unsigned char *auth,
	      const unsigned char *secret, unsigned secret_len,
	      const unsigned char *key, unsigned key_len,
	      unsigned char *out)
{
  unsigned i;
  for (i = 0; i < key_len; i += 16) {
    MD5_CTX md5_ctxt;
    unsigned char b[16];
    unsigned j;

    MD5_Init (&md5_ctxt);
    MD5_Update (&md5_ctxt, secret, secret_len);
    if (i == 0) {
      MD5_Update (&md5_ctxt, auth, 16);
      MD5_Update (&md5_ctxt, salt, 2);
    }
    else
      MD5_Update (&md5_ctxt, out + i - 16, 16);
    MD5_Final (b, &md5_ctxt);

    for (j = 0; j < 16; j++) {
      unsigned char p;
      if (i + j >= key_len)
	p = 0;
      else
	p = key[i + j];
      out[i + j] = p ^ b[j];
    }
  }
}

static void
app_radius_mppe (unsigned char *rep, unsigned *off,
		 unsigned vendor_type, unsigned char *key_mat,
		 unsigned char *auth)
{
  unsigned char mppe_attr[4 + 2 + 2 + 48];
  unsigned char mppe_in[32 + 1];

  write32(mppe_attr, 0x137);  /* MS vendor */
  mppe_attr[4] = vendor_type;        /* Type: ms-mppe-recv-key */
  mppe_attr[5] = 2 + 2 + 48;
  RAND_bytes(mppe_attr + 6, 2);  /* salt */
  mppe_attr[6] |= 0x80;

  mppe_in[0] = 32; /* key length */
  memcpy (mppe_in + 1, key_mat, 32);
  mppe_encrypt(mppe_attr + 6, auth, secret, secret_len,
	       mppe_in, sizeof mppe_in, mppe_attr + 8);

  app_radius_attr(rep, off, ATTR_VENDOR_SPECIFIC, mppe_attr, sizeof mppe_attr);
}

static void
BIO_discard(BIO *bio, unsigned len)
{
  char buf[1024];

  while (len > 0) {
    unsigned l = len > sizeof buf ? sizeof buf : len;
    BIO_read(bio, buf, l);
    len -= l;
  }
}

static int
do_eap_tun_in(struct udp_pkt *pkt, struct eap_ctxt *s,
	      unsigned char *req, unsigned reqlen)
{
  unsigned char eap_id;
  unsigned char pflags;

  /* Ok, we have something for TLS.  */
  if (s->state == S_INIT) {
    s->mem_rd = BIO_new(BIO_s_mem());
    s->mem_wr = BIO_new(BIO_s_mem());
    if (s->mem_rd == NULL || s->mem_wr == NULL) {
      log_err("cannot allocate BIO\n");
      BIO_free(s->mem_rd);
      BIO_free(s->mem_wr);
      return -1;
    }
    s->ssl = SSL_new(ssl_ctxt);
    if (s->ssl == NULL) {
      log_err("cannot allocate SSL\n");
      BIO_free(s->mem_rd);
      BIO_free(s->mem_wr);
      return -1;
    }
    SSL_set_bio(s->ssl, s->mem_rd, s->mem_wr);
    s->state = S_HANDSHAKE;
    s->rx_tx = 1;
    s->cur_len = 0;
    s->last_len = 0;
    s->total_len = 0;
  }

  /* Inspect packet.  */
  assert(req[0] == EAP_CODE_RESPONSE);
  s->rad_id = pkt->req[1];
  eap_id = req[1];
  pflags = req[5];

  if (pflags & PEAP_FLAG_START) {
    log_err ("Unexpected start\n");
    return -1;
  }
  if ((pflags & PEAP_FLAG_MASK) == 0 && reqlen == 6) {
    /* An ACK.  */
    unsigned char *b;
    long len;
    unsigned off;
    unsigned char rsp[6];

    if (s->rx_tx != 1) {
      /* Was not transmitting, or packet fully transmitted.  */
      log_err ("Unexpected ACK\n");
      return -1;
    }
    if (s->last_id != eap_id) {
      log_err ("ACK for an unknown packet\n");
      return -1;
    }
    /* ACK.  Discard bytes, send the next packet.  */
    BIO_discard(s->mem_wr, s->last_len);
    s->cur_len += s->last_len;

    len = BIO_get_mem_data(s->mem_wr, (char **)&b);
    if (flag_dump)
      dump_log ("### ack - total: %u, cur: %u, rem: %u, bio len: %u\n",
		s->total_len, s->cur_len, s->total_len - s->cur_len,
		(unsigned)len);
    if (len == 0) {
      assert (s->cur_len == s->total_len);
    }
    else {
      s->last_id = eap_id + 1;
      if (len > MTU)
	len = MTU;
      s->last_len = len;

      /* Send the next fragment.  */
      app_radius_hdr(pkt->rep, &off,
		     CODE_ACCESS_CHALLENGE, s->rad_id, pkt->req + 4);

      rsp[0] = EAP_CODE_REQUEST;
      rsp[1] = s->last_id;
      rsp[2] = 0;       /* len */
      rsp[3] = 0;
      rsp[4] = EAP_TYPE_PEAP;
      rsp[5] = s->cur_len + len < s->total_len ? PEAP_FLAG_MORE : 0;
      app_radius_peap(pkt->rep, &off, rsp, sizeof rsp, b, len);

      app_radius_attr(pkt->rep, &off, ATTR_STATE,
		      s->radius_state, sizeof s->radius_state);

      return compute_eap_authenticator(pkt->rep, off);
    }
  }
  else {
    /* 3 possibilities:
       - Either a new packet (with flag LEN)
       - Either a new packet (without flag LEN if the packet is small enough)
       - Or a new fragment (with or without the MORE flag)
    */
    if (s->rx_tx != 1) {
      log_err ("Unexpected data - need to transmit\n");
      return -1;
    }
    /* TODO: retransmission of the last packet. */
    BIO_discard(s->mem_wr, s->last_len);

    if (s->cur_len + s->last_len == s->total_len) {
      /* This must be a new packet.  */
      s->rx_tx = 0;
      s->cur_len = 0;
      s->last_id = eap_id;
      if (pflags & PEAP_FLAG_LEN) {
	/* A new packet with LEN */
	s->total_len = read32(req + 6);
	s->last_len = reqlen - 10;

	req += 10;
	reqlen -= 10;
      }
      else {
	/* A new packet without LEN */
	s->last_len = reqlen - 6;
	s->total_len = s->last_len;
	req += 6;
	reqlen -= 6;
      }
    }
    else {
      /* A fragment  */
      if (pflags & PEAP_FLAG_LEN) {
	log_err ("PEAP: unexpected LEN flag\n");
	return -1;
      }
      req += 6;
      reqlen -= 6;
    }

    if (BIO_write(s->mem_rd, req, reqlen) != (int)reqlen) {
      log_err ("BIO_write error\n");
      return -1;
    }

    assert(s->rx_tx == 0);
    if (s->cur_len + s->last_len < s->total_len) {
      log_err ("TODO: need to send ACK\n");
      return -1;
    }
  }

  if (flag_dump) {
    unsigned char *b;
    long len;
    len = BIO_get_mem_data(s->mem_rd, (char **)&b);
    dump_log ("TLS: recv %ld bytes\n", len);
    dump_tls (b, len);
  }
  return 0;
}

static int
do_eap_tun_out(struct udp_pkt *pkt, struct eap_ctxt *s,
	       unsigned char *req)
{
  unsigned char *b;
  long len;
  unsigned eap_id = req[1];

  len = BIO_get_mem_data(s->mem_wr, (char **)&b);

  if (flag_dump) {
    dump_log ("TLS: send %ld bytes\n", len);
    dump_tls (b, len);
  }

  if (0)
    dump_log ("BIO get_mem_data: %u\n", (unsigned)len);
  if (len != 0) {
    unsigned off;
    unsigned char rsp[10];

    s->rx_tx = 1;
    s->total_len = len;
    s->cur_len = 0;
    s->last_id = eap_id + 1;
    if (len > MTU)
      len = MTU;
    s->last_len = len;

    /* Prepare the response.  */
    app_radius_hdr(pkt->rep, &off,
		   CODE_ACCESS_CHALLENGE, s->rad_id, pkt->req + 4);

    rsp[0] = EAP_CODE_REQUEST;
    rsp[1] = s->last_id;
    rsp[2] = 0;       /* len */
    rsp[3] = 0;
    rsp[4] = EAP_TYPE_PEAP;
    rsp[5] = PEAP_FLAG_LEN | ((unsigned)len < s->total_len ? PEAP_FLAG_MORE : 0);
    write32(rsp + 6, s->total_len);
    app_radius_peap(pkt->rep, &off, rsp, sizeof rsp, b, len);

    app_radius_attr(pkt->rep, &off, ATTR_STATE,
		    s->radius_state, sizeof s->radius_state);

    return compute_eap_authenticator(pkt->rep, off);
  }
  log_err ("SSL wants to read after rx!\n");
  return -1;
}

static void
do_eap_peap_ident(struct eap_ctxt *s)
{
  /* Send EAP req id */
  unsigned char req[5];
  req[0] = EAP_CODE_REQUEST;
  req[1] = 1;
  req[2] = 0;
  req[3] = 5;
  req[4] = EAP_TYPE_IDENTITY;
  if (flag_dump) {
    dump_log ("#SSL send eap (identity):\n");
    dump_hex (" ", req, sizeof req);
    dump_eap_message(req, sizeof req);
  }
  SSL_write (s->ssl, req, sizeof req);
}

static int
do_eap_peap_challenge(struct eap_ctxt *s)
{
  switch (s->proto_auth) {
  case EAP_TYPE_MD5_CHALLENGE:
    {
      unsigned char rsp[2 + sizeof s->challenge + 2];

      /* Send Challenge. */
      rsp[0] = EAP_TYPE_MD5_CHALLENGE;
      rsp[1] = sizeof s->challenge;  /* value size */
      RAND_bytes(s->challenge, sizeof s->challenge);
      memcpy (rsp + 2, s->challenge, sizeof s->challenge);  /* value */
      memcpy (rsp + 2 + sizeof s->challenge, "mr", 2);      /* name */
      if (flag_dump) {
	dump_log ("SSL send challenge\n");
	dump_eap_response(rsp, sizeof rsp);
      }
      SSL_write (s->ssl, rsp, sizeof rsp);
      return 0;
    }
    break;
  case EAP_TYPE_MS_CHAP_V2:
    {
      unsigned char rsp[6 + sizeof s->challenge + 2];

      /* Send Challenge. draft-kamath-pppext-eap-mschapv2-02 */
      rsp[0] = EAP_TYPE_MS_CHAP_V2;
      rsp[1] = 1; /* Challenge */
      rsp[2] = s->last_id; /* id */
      write16(rsp + 3, sizeof rsp - 1); /* len */
      rsp[5] = sizeof s->challenge;  /* value size */
      RAND_bytes(s->challenge, sizeof s->challenge);
      memcpy (rsp + 6, s->challenge, sizeof s->challenge);  /* value */
      memcpy (rsp + 6 + sizeof s->challenge, "mr", 2);      /* name */
      if (flag_dump) {
	dump_log ("SSL send ms-chap-v2 challenge\n");
	dump_hex (" ", rsp, sizeof rsp);
	dump_eap_response(rsp, sizeof rsp);
      }
      SSL_write (s->ssl, rsp, sizeof rsp);
      return 0;
    }
  default:
    log_err("internal error: unhandled auth method %u (in req)\n",
	    s->proto_auth);
    return -1;
  }
}

/* Check response. -1: error, 0: reject, 1: ok */
static int
do_eap_peap_challenge_response(struct eap_ctxt *s,
			       unsigned char *req,
			       unsigned char *rep, unsigned len)
{
  switch (s->proto_auth) {
  case EAP_TYPE_MD5_CHALLENGE:
    {
      /* Check result.
	 RFC 1994: the response value is the one-way hash calculated over
	 a stream of octets consisting of the Identifier, followed by
	 (concatenated with) the "secret", followed by (concatenated with)
	 the Challenge Value. */
      if (len < 16 + 2 || rep[1] != 16) {
	log_err("Recv-Challenge: bad challenge reply length\n");
	return -1;
      }
      if (s->user) {
	MD5_CTX md5_ctxt;
	unsigned char challenge[16];

	MD5_Init (&md5_ctxt);
	MD5_Update (&md5_ctxt, req + 1, 1); /* Identifier */
	MD5_Update (&md5_ctxt, s->user->pass, strlen (s->user->pass));
	MD5_Update (&md5_ctxt, s->challenge, sizeof s->challenge);
	MD5_Final (challenge, &md5_ctxt);

	return memcmp (challenge, rep + 2, sizeof challenge) == 0;
      }
      else {
	return 0;
      }
    }
    break;
  case EAP_TYPE_MS_CHAP_V2:
    {
      if (len < 55
	  || rep[1] != 2 /* Opcode */
	  /* || rep[2] != s->last_id  * Id, TODO */
	  || read16(rep + 3) < 6 + 49 /* ms-length */
	  || rep[5] != 49 /* Value-size */
	  || rep[6 + 16 + 8 + 24] != 0  /* Response Flag */
	  ) {
	log_err("Recv-Challenge: bad challenge reply length\n");
	return -1;
      }
      if (s->user) {
	const unsigned char *peer_challenge = rep + 6;
	const char *user_name = s->user->name;
	const char *pass = s->user->pass;
	const unsigned char *challenge = s->challenge;
	const unsigned char *expected_nt_resp = rep + 6 + 24;
	int res;

	res = mschapv2_ntresp (challenge, peer_challenge,
			       user_name, pass,
			       expected_nt_resp,
			       s->auth_string);
	if (flag_dump)
	  dump_log("ms-chap-v2 nt-resp: %d\n", res);
	return res == 0;
      }
      else {
	return 0;
      }
    }
    break;
  default:
    log_err("internal error: unhandled auth method %u (in resp)\n",
	    s->proto_auth);
    return -1;
  }
}

static void
do_eap_peap_result_request(struct eap_ctxt *s)
{
  unsigned char rsp[64];
  unsigned char l;
  
  switch (s->proto_auth) {
  case EAP_TYPE_MD5_CHALLENGE:
    {
      /* Result.  See [MS-PEAP] */
      /* EAP Packet */
      rsp[0] = EAP_CODE_REQUEST;
      rsp[1] = s->last_id + 1;  /* id */
      rsp[2] = 0;       /* len */
      rsp[4] = EAP_TYPE_PEAP_EXTENSION;
      /* Result TLV */
      write16(rsp + 5, EAP_ETYPE_RESULT);  /* Madatory AVP result */
      rsp[7] = 0;    /* Length */
      rsp[8] = 2;
      rsp[9] = 0;  /* result */
      rsp[10] = s->success ? RESULT_SUCCESS : RESULT_FAILURE;

      l = 11;
      rsp[3] = l;
    }
    break;
  case EAP_TYPE_MS_CHAP_V2:
    {
      l = 0;
#if 0
      rsp[0] = EAP_CODE_REQUEST;
      rsp[1] = s->last_id + 1;  /* id */
      rsp[2] = 0;       /* len */
      l = 3;
#endif

      if (s->success) {
	rsp[l++] = EAP_TYPE_MS_CHAP_V2;
	rsp[l++] = EAP_CODE_SUCCESS;
	rsp[l++] = s->last_id + 1;
	l += 2; /* 2 bytes for the length field. */
	rsp[l++] = 'S';
	rsp[l++] = '=';
	write_hex(rsp + l, s->auth_string, sizeof (s->auth_string)); /* 20 */
	l += 40;
	rsp[l++] = ' ';
	rsp[l++] = 'M';
	rsp[l++] = '=';
	rsp[l++] = 'O';
	rsp[l++] = 'k';
      }
      else {
	rsp[l++] = EAP_TYPE_MS_CHAP_V2;
	rsp[l++] = EAP_CODE_FAILURE;
	rsp[l++] = s->last_id + 1;
	l += 2; /* 2 bytes for the length field. */
	memcpy (rsp + l, "E=691 R=0 C=", 12);
	l += 12;
	write_hex(rsp + l, s->challenge, 16);
	l += 32;
	rsp[l++] = ' ';
	rsp[l++] = 'V';
	rsp[l++] = '=';
	rsp[l++] = '3';
	rsp[l++] = ' ';
	rsp[l++] = 'M';
	rsp[l++] = '=';
	rsp[l++] = 'K';
	rsp[l++] = 'O';
      }
      write16 (rsp + 3, l - 1);
    }
    break;
  default:
    log_err("eap peap result request: unhandled auth %u\n", s->proto_auth);
    abort();
  }

  if (flag_dump) {
    dump_log ("SSL send result\n");
    dump_hex(" ", rsp, l);
    dump_eap_message(rsp, l);
  }
  SSL_write (s->ssl, rsp, l);
}

static int
do_eap_peap(struct udp_pkt *pkt, struct eap_ctxt *s,
	    unsigned char *req, unsigned reqlen)
{
  int res;
  int len = 0;

  /* Handle only PEAP.  */
  if (req[4] != EAP_TYPE_PEAP) {
    log_err ("Unhandled eap response type (%u)\n", req[4]);
    return -1;
  }

  s->last_time = pkt->cur_time;

  res = do_eap_tun_in(pkt, s, req, reqlen);
  if (res != 0)
    return res;

  if (s->state != S_HANDSHAKE) {
    len = SSL_read(s->ssl, pkt->rep, sizeof pkt->rep);
    if (len < 0) {
      int err = SSL_get_error(s->ssl, len);
      if (err == SSL_ERROR_WANT_READ) {
	/* It was only an ACK, no data.  */
	len = 0;
      }
      else {
	log_err ("SSL read error: len=%d, err=%d\n", len, err);
	return -1;
      }
    }
    if (flag_dump && len > 0) {
      dump_log ("##SSL recv eap (len=%u):\n", len);
      dump_hex ("  ", pkt->rep, len);
      dump_eap_response(pkt->rep, len);
    }
  }

  switch (s->state) {
  case S_HANDSHAKE:
    {
      res = SSL_accept(s->ssl);
      if (res == 1) {
	if (0)
	  dump_log ("Handshake accepted\n");

	if (0 && SSL_version(s->ssl) > TLS1_1_VERSION) {
	  /* FIXME ? how to know if this is possible or not ?
	     Re-send in case of ack ?  */
	  do_eap_peap_ident(s);
	  s->state = S_TUN_RECV_IDENTITY;
	}
	else {
	  /* Some clients won't accept data before an ack.  */
	  s->state = S_TUN_SEND_IDENTITY;
	}
      }
      else if (res == 0) {
	log_err ("Handshake failure\n");
	return -1;
      }
      else {
	/* Wait for more data.
	   Send ack.  */
      }
    }
    break;
  case S_TUN_SEND_IDENTITY:
    if (len != 0)
      log_err("Send-Identity: ignore incoming data\n");
    do_eap_peap_ident(s);
    s->state = S_TUN_RECV_IDENTITY;
    break;
  case S_TUN_RECV_IDENTITY:
    {
      if (len < 1 || pkt->rep[0] != EAP_TYPE_IDENTITY) {
	log_err("Recv-Identity: expect identity answer\n");
	return -1;
      }
      /* Copy user name. */
      s->user = get_user(pkt->rep + 1, len - 1);

      s->state = S_TUN_RECV_CHALLENGE;
      if (do_eap_peap_challenge(s) < 0)
	return -1;
    }
    break;
  case S_TUN_RECV_CHALLENGE:
    {
      if (len < 1 || pkt->rep[0] != s->proto_auth) {
	if (len >= 1 && pkt->rep[0] == EAP_TYPE_NAK) {
	  if (len == 1) {
	    log_err("Recv-Challenge: nak and no auth protocol\n");
	    return -1;
	  }
	  /* Try next protocol.  TODO: check if supported.  */
	  if (s->proto_auth == EAP_TYPE_MS_CHAP_V2) {
	    log_err("Recv-Challenge: nak and proto exhausted\n");
	    return -1;
	  }
	  s->proto_auth = EAP_TYPE_MS_CHAP_V2;
	  if (do_eap_peap_challenge(s) < 0)
	    return -1;
	  /* Else: send the packet */
	}
	else {
	  log_err("Recv-Challenge: protocol error\n");
	  return -1;
	}
      }
      else {
	/* Check result.  */
	int res;
	const char *err;

	res = do_eap_peap_challenge_response(s, req, pkt->rep, len);
	s->success = 0;

	if (res < 0)
	  return -1;
	else if (res == 0) {
	  if (s->user)
	    err = " (wrong password)";
	  else
	    err = " (unknown user)";
	}
	else {
	  if (pkt->cur_time >= s->user->timeout)
	    err = " (timeout)";
	  else {
	    err = "";
	    s->success = 1;
	  }
	}

	/* Log */
	{
	  static const char wday_name[12][4] = {
	    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
	  };
	  static const char mon_name[12][4] = {
	    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	  };
	  struct tm tm;

	  /* If the time is obviously wrong, don't try to convert it to
	     local time.  */
	  if (pkt->cur_time > (time_t)(24 * 3600 * 365 * 20))
	    localtime_r(&pkt->cur_time, &tm);
	  else
	    gmtime_r(&pkt->cur_time, &tm);

#if 0
	  asctime_r(&tm, tbuf);

	  /* The output of asctime is a string of the form:
	     Thu Nov 24 18:22:48 1986\n\0
	  */
	  assert(tbuf[26] == 0);
	  assert(tbuf[25] == '\n');
	  tbuf[25] = 0;
#endif

	  log_info("%s %s %2d %02d:%02d:%02d %d: user %s %s%s\n",
		   wday_name[tm.tm_wday], mon_name[tm.tm_mon],
		   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
		   1900 + tm.tm_year,
		   s->user ? s->user->name : "(unknown)",
		   s->success ? "accepted" : "rejected",
		   err);
	}

	do_eap_peap_result_request(s);

	s->state = S_TUN_RECV_RESULT;
      }
    }
    break;

  case S_TUN_RECV_RESULT:
    {
      /* Send EAP-success */
      unsigned char rsp[4];
      unsigned off;
      unsigned eresult = s->success ? RESULT_SUCCESS : RESULT_FAILURE;
      /* Keying material.  */
      unsigned char key_mat[128];
      static const char label[] = "client EAP encryption"; /* RFC 5216 2.3 */

      switch (s->proto_auth) {
      case EAP_TYPE_MD5_CHALLENGE:
	{
	  if (len != 11
	      || pkt->rep[0] != EAP_CODE_RESPONSE
	      // || pkt->rep[1] != 6 /* id */
	      || read16(pkt->rep + 2) != 11 /* len */
	      || pkt->rep[4] != EAP_TYPE_PEAP_EXTENSION
	      || read16(pkt->rep + 5) != EAP_ETYPE_RESULT
	      || read16(pkt->rep + 7) != 2) {
	    log_err("Recv-Result: non-result packet\n");
	    return -1;
	  }
	  if (read16(pkt->rep + 9) != eresult) {
	    log_err("Recv-Result: result mismatch!\n");
	    return -1;
	  }
	}
	break;
      case EAP_TYPE_MS_CHAP_V2:
	if (s->success) {
	  if (len != 2
	      || pkt->rep[0] != EAP_TYPE_MS_CHAP_V2
	      || pkt->rep[1] != 3 /* Success */
	      ) {
	    log_err("Recv-Result: non-success packet\n");
	    return -1;
	  }
	}
	else {
	  if (len != 2
	      || pkt->rep[0] != EAP_TYPE_MS_CHAP_V2
	      || pkt->rep[1] != 4 /* Failure */
	      ) {
	    log_err("Recv-Result: non-failure packet\n");
	    return -1;
	  }
	}
	break;
      default:
	log_err("Recv tunnel proto: unhandled auth %u\n", s->proto_auth);
	abort();
      }

      app_radius_hdr(pkt->rep, &off,
		     s->success ? CODE_ACCESS_ACCEPT : CODE_ACCESS_REJECT,
		     s->rad_id, pkt->req + 4);
      if (s->user) {
	unsigned ulen = strlen(s->user->name);
	app_radius_attr(pkt->rep, &off, ATTR_USER_NAME,
			(const unsigned char *)s->user->name, ulen);
      }

      if (s->success) {
	unsigned char timeout[4];
	unsigned t;

	if (SSL_export_keying_material(s->ssl, key_mat, sizeof (key_mat),
				       label, sizeof(label) - 1,
				       NULL, 0, 0) != 1) {
	  log_err ("SSL_export keying error\n");
	  return -1;
	}

	/* Encrypt recv and send keys.  RFC 2548 2.4.2 */
	app_radius_mppe(pkt->rep, &off, 0x11, key_mat, pkt->req + 4);
	app_radius_mppe(pkt->rep, &off, 0x10, key_mat + 32, pkt->req + 4);

	/* Session timeout.  */
	if (s->user->timeout <= pkt->cur_time) {
	  /* Timeout occured during renewval.  */
	  t = 5;
	}
	else {
	  t = (unsigned)(s->user->timeout - pkt->cur_time);
	  if (t > 5 * 60)
	    t = 5 * 60;
	}
	write32(timeout, t);
	app_radius_attr(pkt->rep, &off, ATTR_SESSION_TIMEOUT,
			timeout, sizeof timeout);
      }

      rsp[0] = s->success ? EAP_CODE_SUCCESS : EAP_CODE_FAILURE;
      rsp[1] = s->last_id + 1;
      rsp[2] = 0;       /* len */
      rsp[3] = 4;
      app_radius_eap(pkt->rep, &off, rsp, sizeof rsp);

      return compute_eap_authenticator(pkt->rep, off);
    }
  default:
    log_err ("Unhandled SSL state\n");
    return -1;
  }

  res = do_eap_tun_out(pkt, s, req);
  return res;
}

/* Handle incoming eap message. */
static int
handle_eap_message(struct udp_pkt *pkt, unsigned char *state,
		   unsigned char *eap, unsigned eap_len)
{
  struct eap_ctxt *ctxt;

  /* Sanity check.  */
  if (eap_len < 4) {
    log_err ("Bad EAP-Message packet length\n");
    return -1;
  }

  if (read16(eap + 2) != eap_len) {
    log_err ("Bad EAP-Message length field\n");
    return -1;
  }

  /* Find the context.  */
  ctxt = NULL;
  if (state != NULL) {
    unsigned i;
    for (i = 0; i < NBR_EAP_CTXTS; i++) {
      ctxt = &eap_ctxts[i];
      /* TODO: check IP saddr, UDP sport.  */
      if (ctxt->state != S_FREE
	  && state[1] - 2 == sizeof (ctxt->radius_state)
	  && memcmp (state + 2,
		     ctxt->radius_state, sizeof ctxt->radius_state) == 0)
	break;
      ctxt = NULL;
    }
    if (ctxt == NULL) {
      log_err ("State present but not found\n");
      return -1;
    }
  }

  if (eap[0] == EAP_CODE_RESPONSE) {
    if (eap_len < 5)
      return -1;

    if (ctxt == NULL) {
      /* First packet.  */
      if (eap[4] == EAP_TYPE_IDENTITY) {
	/* This is the first message: the identity has been transmitted,
	   time to challenge.  */
	/* Create a context:
	   - ip+port, random, number
	   - extract user
	   - extract MTU
	   - extract calling station id, called station id...
	*/
	return do_eap_init(pkt, eap, eap_len);
      }
      else {
	log_err ("eap response without a context\n");
	return -1;
      }
    }
    else {
      return do_eap_peap(pkt, ctxt, eap, eap_len);
    }
  }
  else {
    log_err ("Unhandled eap code (%u)\n", eap[0]);
  }

  return 0;
}

static int
handle_access_request(struct udp_pkt *pkt)
{
  unsigned char eap_buf[4096];
  unsigned eap_len = 0;
  unsigned char *state;
  unsigned off;

  /* Find and gather EAP-Message, find State.  */
  eap_len = 0;
  state = NULL;
  for (off = 20; off < pkt->reqlen; ) {
    unsigned alen = pkt->req[off + 1];

    if (pkt->req[off] == ATTR_EAP_MESSAGE) {
      memcpy (eap_buf + eap_len, pkt->req + off + 2, alen - 2);
      eap_len += alen - 2;
    }
    else if (pkt->req[off] == ATTR_STATE)
      state = pkt->req + off;
    off += pkt->req[off + 1];
  }

  if (eap_len != 0) {
    int auth;

    if (flag_dump) {
      dump_log ("EAP message(full) len=%u:\n", eap_len);
      dump_eap_message(eap_buf, eap_len);
    }

    /* Authenticate. */
    auth = auth_request(pkt->req, pkt->reqlen);
    if (auth < 0) {
      log_err ("Authentification failed\n");
      return -1;
    }
    else if (auth == 0) {
      log_err ("Non authentified packet\n");
      return -1;
    }

    return handle_eap_message(pkt, state, eap_buf, eap_len);
  }
  else {
    log_err ("not handled: non-EAP request\n");
    return -1;
  }
}

/* Check the request PKT is well-formed (attributes length is ok). */
static int
check_radius_packet(struct udp_pkt *pkt, unsigned plen)
{
  unsigned off;

  if (plen < 20 || plen > 4096)
    return -1;
  pkt->reqlen = read16(pkt->req + 2);
  if (pkt->reqlen < 20 || pkt->reqlen > plen)
    return -1;

  for (off = 20; off < pkt->reqlen; ) {
    unsigned rlen = pkt->reqlen - off;
    unsigned alen;

    if (rlen < 2) {
      /* Need at least two bytes for an attribute.  */
      return -1;
    }
    alen = pkt->req[off + 1];
    if (alen > rlen) {
      /* Length of the attribute exceed the packet length.  */
      return -1;
    }
    off += alen;
  }
  return 0;
}

/* Initialize openssl, read certificate and private key.  */
static SSL_CTX *
init_openssl(void)
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  method = SSLv23_server_method();

  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  SSL_CTX_set_ecdh_auto(ctx, 1);
  if (config_ssl(ctx) < 0)
    return NULL;

  if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) {
    log_err("failed setting TLS max proto version\n");
  }

  return ctx;
}

static int
server(unsigned flag_write)
{
  int sock;
  struct sockaddr_in myaddr;
  int bin_log = -1;

  ssl_ctxt = init_openssl();
  if (ssl_ctxt == NULL)
    return 1;

  sock = socket (PF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("cannot create socket");
    return 1;
  }

  /* Bind on any interface.  */
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(port);

  if (bind (sock, (struct sockaddr *) &myaddr, sizeof myaddr) < 0) {
    perror("cannot bind socket");
    return 1;
  }

  if (flag_write) {
    bin_log = open("miniradius.pkt", O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (bin_log < 0) {
      perror("cannot open log file");
      return 2;
    }
  }

  while (1) {
    struct udp_pkt upkt;
    socklen_t alen;
    int res;
    int r;

    upkt.fd = sock;
    alen = sizeof(upkt.caddr);

    r = recvfrom(sock, upkt.req, sizeof upkt.req, 0,
                 (struct sockaddr *)&upkt.caddr, &alen);
    if (r < 0) {
      if (errno == EAGAIN)
	continue;
      perror("cannot receive from socket");
      return 1;
    }

    if (time (&upkt.cur_time) == (time_t)-1) {
      log_err("cannot get current_time\n");
      upkt.cur_time = 0;
    }

    if (flag_dump) {
      struct sockaddr_in *sin = (struct sockaddr_in *)&upkt.caddr;
      dump_log ("### from: %s port %u, len: %u\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), r);
      dump_radius(upkt.req, r);
    }

    /* Discard invalid packets.  */
    if (check_radius_packet(&upkt, r) < 0) {
      log_err ("bad radius packet\n");
      continue;
    }

    if (flag_write)
      write(bin_log, upkt.req, upkt.reqlen);

    /* Handle packet.  */
    switch (upkt.req[0]) {
    case CODE_ACCESS_REQUEST:
      res = handle_access_request(&upkt);
      break;
    default:
      log_err ("unhandled radius req 0x%02x\n", upkt.req[0]);
      res = 0;
      break;
    }

    if (res <= 0) {
      /* Nothing to send. */
      continue;
    }

    /* Send reply. */
    if (flag_dump) {
      struct sockaddr_in *sin = (struct sockaddr_in *)&upkt.caddr;
      dump_log ("### to: %s port %u, len: %u\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), res);
      dump_radius(upkt.rep, res);
    }

    if (flag_write)
      write(bin_log, upkt.rep, res);

    r = sendto (sock, upkt.rep, res, 0,
                (struct sockaddr *)&upkt.caddr, sizeof upkt.caddr);
    if (r != res)
      perror ("sendto");
  }
}

int
main (int argc, char *argv[])
{
  const char *progname = argv[0];
  unsigned flag_dump_pcap = 0;
  unsigned flag_write = 0;

  if (config_init(argc, argv) < 0) {
    log_err("failed to initialize configuration\n");
    return 1;
  }

  /* Skip progname. */
  argv++;
  argc--;

  /* Simple option decoder.  */
  while (argc > 0) {
    if (strcmp (argv[0], "-de") == 0)
      dump_eap_only = 1;
    else if (strcmp (argv[0], "-d") == 0)
      flag_dump = 1;
    else if (strcmp (argv[0], "-r") == 0)
      flag_dump_pcap = 1;
    else if (strcmp (argv[0], "-W") == 0)
      flag_write = 1;
    else if (strcmp(argv[0], "-R") == 0)
      return dump_packets();
    else if (strcmp(argv[0], "-s") == 0) {
      if (argc < 2) {
	fprintf (stderr, "missing value for option -s\n");
	return 2;
      }
      secret = (unsigned char *)argv[1];
      secret_len = strlen(argv[1]);
      argv++;
      argc--;
    }
    else {
      fprintf (stderr, "unknown option %s\n", argv[0]);
      return 2;
    }
    argv++;
    argc--;
  }

  if (flag_dump_pcap)
    return dump_pcap(port);

  if (secret == NULL) {
    fprintf (stderr, "%s: missing secret option (-s SECRET)\n", progname);
    return 2;
  }

  return server(flag_write);
}
