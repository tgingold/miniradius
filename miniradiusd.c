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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#include "hmac_md5.h"
#include "radius.h"
#include "dump.h"

static unsigned flag_dump = 0;

unsigned port = 1812;

static SSL_CTX *ssl_ctxt;

#define BUF_LEN 4096
#define MTU 1024

struct udp_addr {
  unsigned fd;
  struct sockaddr caddr;

  unsigned char req[BUF_LEN];
  unsigned char rep[BUF_LEN];
  unsigned reqlen;
  unsigned replen;
};

struct eap_ctxt {
  struct sockaddr peer_addr;
  uint16_t mtu;
  uint8_t rad_id;

  /* Timeouts */

  /* Radius-State */
  unsigned char radius_state[4];

  /* State:
     0: unused
     1: init tls sent (protocol, list of protocol)
     2: in TLS handshake
  */
  enum eap_state { S_FREE, S_INIT, S_HANDSHAKE, S_TUNNEL } state;

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

  unsigned char user_name[32];
};

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
write32 (unsigned char *p, uint32_t v)
{
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v >> 0;
}

/* Radius shared secret between this server and the clients.  */
static unsigned char *secret;
static unsigned secret_len;

/* Check authenticator attribute.
   Return 1 if OK, -1 if error, 0 if not present.  */
static int
auth_request(unsigned char *p, int plen)
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
		unsigned char *reqauth)
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
		unsigned char code, unsigned char *buf, unsigned len)
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
		unsigned char *buf, unsigned len)
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

static int
do_eap_challenge(unsigned char *req, int rea_len,
		 unsigned char *eap, int eap_len,
		 unsigned char *rep)
{
  unsigned off;
  unsigned char *r;
  unsigned len;
  unsigned char *p_mac;

  /* Header.  */
  app_radius_hdr(rep, &off, CODE_ACCESS_CHALLENGE, req[1], req + 4);

  /* What do we put ?
     Copy proxy, create state... */
  r = rep + off;

  r[0] = ATTR_EAP_MESSAGE;
  r[1] = 0;
  r[2] = EAP_CODE_REQUEST;
  r[3] = eap[1] + 1;  /* id */
  r[4] = 0;       /* len */
  r[5] = 0;
  if (0) {
    r[6] = EAP_TYPE_OTP;
    memcpy (r + 7, "otp-md5 487 dog2 ", 17);
    r[5] = 4 + 1 + 17;
  }
  else if (0) {
    r[6] = EAP_TYPE_MD5_CHALLENGE;
    r[7] = 8;  /* value size */
    memcpy (r + 8, "\x12\x34\x56\x78\x9a\xbc\xde\xf0", 8);  /* value */
    memcpy (r + 16, "MRname", 6);
    r[5] = 4 + 2 + 8 + 6;
  }
  else if (1) {
    r[6] = EAP_TYPE_PEAP;
    r[7] = PEAP_FLAG_START;
    r[5] = 4 + 2;
  }
  else if (0) {
    r[6] = EAP_TYPE_EAP_TTLS;
    r[7] = 0x20;  /* start */
    r[5] = 4 + 2;
  }
  else if (0) {
    r[6] = EAP_TYPE_EAP_TLS;
    r[7] = 0x20;  /* start */
    r[5] = 4 + 2;
  }
  r[1] = r[5] + 2;
  r += r[1];

  /* Auth */
  r[0] = ATTR_MESSAGE_AUTHENTICATOR;
  r[1] = 18;
  p_mac = r + 2;
  memset (p_mac, 0, 16);
  r += r[1];

  /* State */
  r[0] = ATTR_STATE;
  r[1] = 18;
  r[ 2] = 0x59;
  r[ 3] = 0x35;
  r[ 4] = 0xa8;
  r[ 5] = 0x59;
  r[ 6] = 0x59;
  r[ 7] = 0x34;
  r[ 8] = 0xa5;
  r[ 9] = 0xd2;
  r[10] = 0x70;
  r[11] = 0x91;
  r[12] = 0x10;
  r[13] = 0xd2;
  r[14] = 0xbd;
  r[15] = 0x37;
  r[16] = 0xa5;
  r[17] = 0x5e;
  r += r[1];

  len = compute_eap_authenticator_noalloc(rep, r - rep, p_mac);

  return len;
}

static int
do_eap_auth(unsigned char *req, int rea_len,
	    unsigned char *eap, int eap_len,
	    unsigned char *rep)
{
  unsigned char *r;
  unsigned len;

  /* Header.  */
  rep[0] = CODE_ACCESS_ACCEPT;
  rep[1] = req[1];
  rep[2] = 0;
  rep[3] = 0;

  /* Authenticator: copy RequestAuth.  */
  memcpy(rep + 4, req + 4, 16);

  /* What do we put ?
     Copy proxy, create state... */
  r = rep + 20;

  r[0] = ATTR_EAP_MESSAGE;
  r[1] = 0;
  r[2] = EAP_CODE_SUCCESS;
  r[3] = eap[1];  /* id */
  r[4] = 0;       /* len */
  r[5] = 4;
  r += r[1];

  len = compute_eap_authenticator(rep, r - rep);

  return len;
}

static int
do_eap_init(struct udp_addr *pkt,
	    unsigned char *req, unsigned reqlen)
{
  struct eap_ctxt *ctxt;
  unsigned char rsp[6];
  unsigned off;
  unsigned i;

  /* Find a free context.  */
  ctxt = NULL;
  for (i = 0; i < NBR_EAP_CTXTS; i++)
    if (eap_ctxts[i].state == S_FREE) {
      ctxt = &eap_ctxts[i];
      ctxt->state = S_INIT;
      ctxt->radius_state[0] = i;
      break;
    }
  if (ctxt == NULL) {
    printf ("No context available\n");
    return -1;
  }

  /* Fill the context. */
  memcpy (&ctxt->peer_addr, &pkt->caddr, pkt->caddr.sa_len);
  ctxt->rad_id = pkt->req[1];
  ctxt->last_id = req[1] + 1;

  /* Prepare the response.  */
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

static int
do_eap_peap(struct udp_addr *pkt, struct eap_ctxt *s,
	    unsigned char *req, unsigned reqlen)
{
  int res;
  unsigned char eap_id;
  unsigned char pflags;

  /* Ok, we have something for TLS.  */
  if (s->state == S_INIT) {
    s->mem_rd = BIO_new(BIO_s_mem());
    s->mem_wr = BIO_new(BIO_s_mem());
    s->ssl = SSL_new(ssl_ctxt);
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
    printf ("Unexpected start\n");
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
      printf ("Unexpected ACK\n");
      return -1;
    }
    if (s->last_id != eap_id) {
      printf ("ACK for an unknown packet\n");
      return -1;
    }
    /* ACK.  Discard bytes, send the next packet.  */
    BIO_discard(s->mem_wr, s->last_len);
    s->cur_len += s->last_len;

    len = BIO_get_mem_data(s->mem_wr, (char **)&b);
    if (flag_dump)
      printf ("### ack - total: %u, cur: %u, rem: %u, bio len: %u\n",
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
      printf ("Unexpected data - need to transmit\n");
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
	printf ("PEAP: unexpected LEN flag\n");
	return -1;
      }
      req += 6;
      reqlen -= 6;
    }

    if (BIO_write(s->mem_rd, req, reqlen) != reqlen) {
      printf ("BIO_write error\n");
      return -1;
    }

    assert(s->rx_tx == 0);
    if (s->cur_len + s->last_len < s->total_len) {
      printf ("TODO: need to send ACK\n");
      return -1;
    }
  }

  if (s->state == S_HANDSHAKE) {
    res = SSL_accept(s->ssl);
    if (res == 1) {
      if (0)
	printf ("Handshake accepted\n");
      s->state = S_TUNNEL;

      /* Send EAP req id */
#if 1
      unsigned char req[5];
      req[0] = EAP_CODE_REQUEST;
      req[1] = 1;
      req[2] = 0;
      req[3] = 5;
      req[4] = EAP_TYPE_IDENTITY;
      if (flag_dump) {
	printf ("#SSL send eap (init):\n");
	dump_hex (" ", req, sizeof req);
	dump_eap_message(req, sizeof req);
      }
#else
      unsigned char req[1];
      req[0] = EAP_TYPE_IDENTITY;
      printf ("#SSL send eap (init):\n");
      dump_hex (" ", req, sizeof req);
      dump_eap_request(req, sizeof req);
#endif
      SSL_write (s->ssl, req, sizeof req);
    }
    else if (res == 0) {
      printf ("Handshake failure\n");
      return -1;
    }
  }
  else if (s->state == S_TUNNEL) {
    int len;

    len = SSL_read(s->ssl, pkt->rep, sizeof pkt->rep);
    if (len < 0) {
      printf ("SSL read error: len=%d, err=%d\n",
	      len, SSL_get_error(s->ssl, len));
      return -1;
    }
    else {
      if (flag_dump) {
	printf ("##SSL recv eap:\n");
	dump_hex ("  ", pkt->rep, len);
	dump_eap_response(pkt->rep, len);
      }

      if (pkt->rep[0] == EAP_TYPE_IDENTITY) {
	/* Copy user name.
	   TODO: check length.
	 */
	{
	  s->user_name[0] = len - 1;
	  memcpy(s->user_name + 1, pkt->rep + 1, len - 1);
	}
#if 0
	unsigned char rsp[20];
	rsp[0] = EAP_CODE_REQUEST;
	rsp[1] = 2;  /* id */
	rsp[2] = 0;       /* len */
	rsp[3] = 0;
	rsp[4] = EAP_TYPE_MD5_CHALLENGE;
	rsp[5] = 8;  /* value size */
	memcpy (rsp + 5, "\x12\x34\x56\x78\x9a\xbc\xde\xf0", 8);  /* value */
	memcpy (rsp + 5 + 8, "MRname", 6);
	rsp[3] = 4 + 2 + 8 + 6;
#else
	unsigned char rsp[16];
	rsp[0] = EAP_TYPE_MD5_CHALLENGE;
	rsp[1] = 8;  /* value size */
	memcpy (rsp + 2, "\x12\x34\x56\x78\x9a\xbc\xde\xf0", 8);  /* value */
	memcpy (rsp + 2 + 8, "MRname", 6);
#endif
	if (flag_dump) {
	  printf ("SSL send md5 challenge\n");
	  dump_eap_response(rsp, sizeof rsp);
	}
	SSL_write (s->ssl, rsp, sizeof rsp);
      }
      else if (pkt->rep[0] == EAP_TYPE_MD5_CHALLENGE) {
	/* Success.  */
	unsigned char rsp[11];
	rsp[0] = EAP_CODE_REQUEST;
	rsp[1] = 6;  /* id */
	rsp[2] = 0;       /* len */
	rsp[3] = 0;
	rsp[4] = EAP_TYPE_PEAP_EXTENSION;
	rsp[5] = 0x80; /* Mandatory AVP */
	rsp[6] = 0x03; /* Result */
	rsp[7] = 0;    /* Length */
	rsp[8] = 2;
	rsp[9] = 0;  /* Success */
	rsp[10] = 1;
	rsp[3] = sizeof rsp;
	if (flag_dump) {
	  printf ("SSL send result\n");
	  dump_eap_message(rsp, sizeof rsp);
	}
	SSL_write (s->ssl, rsp, sizeof rsp);
      }
      else if (pkt->rep[0] == EAP_CODE_RESPONSE
	       && len == 11
	       && pkt->rep[1] == 6 /* id */
	       && read16(pkt->rep + 2) == 11 /* len */
	       && pkt->rep[4] == EAP_TYPE_PEAP_EXTENSION
	       && read16(pkt->rep + 5) == 0x8003
	       && read16(pkt->rep + 7) == 2
	       && read16(pkt->rep + 9) == 1) {
	/* Send EAP-success */
	unsigned char rsp[4];
	unsigned off;
	/* Keying material.  */
	unsigned char key_mat[128];
	static char label[] = "client EAP encryption"; /* RFC 5216 2.3 */

	app_radius_hdr(pkt->rep, &off,
		       CODE_ACCESS_ACCEPT, s->rad_id, pkt->req + 4);
	app_radius_attr(pkt->rep, &off,
			ATTR_USER_NAME, s->user_name + 1, s->user_name[0]);

	if (SSL_export_keying_material(s->ssl, key_mat, sizeof (key_mat),
				       label, sizeof(label) - 1,
				       NULL, 0, 0) != 1) {
	  printf ("SSL_export keying error\n");
	  return -1;
	}

	/* Encrypt recv and send keys.  RFC 2548 2.4.2 */
	app_radius_mppe(pkt->rep, &off, 0x11, key_mat, pkt->req + 4);
	app_radius_mppe(pkt->rep, &off, 0x10, key_mat + 32, pkt->req + 4);

	rsp[0] = EAP_CODE_SUCCESS;
	rsp[1] = s->last_id + 1;
	rsp[2] = 0;       /* len */
	rsp[3] = 4;
	app_radius_eap(pkt->rep, &off, rsp, sizeof rsp);

	return compute_eap_authenticator(pkt->rep, off);
      }
      else {
	printf ("Unhandled PEAP req in TLS\n");
	return -1;
      }
    }
  }
  else {
    printf ("Unhandled SSL state\n");
    return -1;
  }

  {
    unsigned char *b;
    long len;

    len = BIO_get_mem_data(s->mem_wr, (char **)&b);
    if (0)
      printf("BIO get_mem_data: %u\n", (unsigned)len);
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
      rsp[5] = PEAP_FLAG_LEN | (len < s->total_len ? PEAP_FLAG_MORE : 0);
      write32(rsp + 6, s->total_len);
      app_radius_peap(pkt->rep, &off, rsp, sizeof rsp, b, len);

      app_radius_attr(pkt->rep, &off, ATTR_STATE,
		      s->radius_state, sizeof s->radius_state);

      return compute_eap_authenticator(pkt->rep, off);
    }
    printf ("SSL wants to read after rx!\n");
    return -1;
  }
  printf ("Unhandled peap\n");
  return -1;
}

static int
handle_eap_message(struct udp_addr *pkt, unsigned char *state,
		   unsigned char *eap, unsigned eap_len)
{
  struct eap_ctxt *ctxt;

  /* Sanity check.  */
  if (eap_len < 4) {
    printf ("Bad EAP-Message packet length\n");
    return -1;
  }

  if (read16(eap + 2) != eap_len) {
    printf ("Bad EAP-Message length field\n");
    return -1;
  }

  /* Find the context.  */
  ctxt = NULL;
  if (state != NULL) {
    unsigned i;
    for (i = 0; i < NBR_EAP_CTXTS; i++) {
      ctxt = &eap_ctxts[i];
      if (ctxt->state != S_FREE
	  && state[1] - 2 == sizeof (ctxt->radius_state)
	  && memcmp (state + 2,
		     ctxt->radius_state, sizeof ctxt->radius_state) == 0)
	break;
      ctxt = NULL;
    }
    if (ctxt == NULL) {
      printf ("State present but not found\n");
      return -1;
    }
  }

  if (eap[0] == EAP_CODE_RESPONSE) {
    if (eap_len < 5)
      return -1;

    switch (eap[4]) {
    case EAP_TYPE_IDENTITY:
      /* This is the first message: the identity has been transmitted,
	 time to challenge.  */
      /* Create a context:
	 - ip+port, random, number
	 - extract user
	 - extract MTU
	 - extract calling station id, called station id...
      */
      if (1)
	return do_eap_init(pkt, eap, eap_len);
      else
	return do_eap_challenge(pkt->req, pkt->reqlen, eap, eap_len, pkt->rep);
    case EAP_TYPE_PEAP:
    case EAP_TYPE_EAP_TTLS:
      return do_eap_peap(pkt, ctxt, eap, eap_len);
    case EAP_TYPE_MD5_CHALLENGE:
      return do_eap_auth(pkt->req, pkt->reqlen, eap, eap_len, pkt->rep);
    default:
      printf ("Unhandled eap response type (%u)\n", eap[4]);
      break;
    }
  }
  else {
    printf ("Unhandled eap code (%u)\n", eap[0]);
  }

  return 0;
}

static int
handle_access_request(struct udp_addr *pkt)
{
  unsigned char eap_buf[4096];
  unsigned eap_len = 0;
  unsigned char *state;
  int auth;
  unsigned off;

  auth = auth_request(pkt->req, pkt->reqlen);
  if (auth < 0) {
    printf ("Authentification failed\n");
    return -1;
  }
  else if (auth == 0) {
    printf ("Non authentified packet\n");
    return -1;
  }

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
    if (flag_dump) {
      printf ("EAP message(concat) len=%u:\n", eap_len);
      dump_eap_message(eap_buf, eap_len);
    }
    return handle_eap_message(pkt, state, eap_buf, eap_len);
  }
  else {
    /* TODO: handle non EAP.  */
    printf ("Not handled: non-EAP request\n");
    return -1;
  }
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

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  return ctx;
}

static int
server(unsigned flag_write)
{
  int sock;
  struct sockaddr_in myaddr;
  int bin_log;

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
    struct udp_addr uaddr;
    socklen_t alen;
    int res;
    int r;

    uaddr.fd = sock;
    alen = sizeof(uaddr.caddr);

    r = recvfrom(sock, uaddr.req, sizeof uaddr.req, 0, &uaddr.caddr, &alen);
    if (r < 0) {
      if (errno == EAGAIN)
	continue;
      perror("cannot receive from socket");
      return 1;
    }

    if (flag_dump) {
      if (uaddr.caddr.sa_family == AF_INET) {
	struct sockaddr_in *sin = (struct sockaddr_in *)&uaddr.caddr;
	printf ("### from: %s port %u, len: %u\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), r);
      }
      dump_radius(uaddr.req, r);
    }

    /* Discard invalid packets.  */
    if (r < 20 || r > 4096)
      continue;
    uaddr.reqlen = read16(uaddr.req + 2);
    if (uaddr.reqlen < 20 || uaddr.reqlen > r)
      continue;

    if (flag_write)
      write(bin_log, uaddr.req, uaddr.reqlen);

    /* TODO: check attributes (length)  */

    if (uaddr.req[0] == CODE_ACCESS_REQUEST)
      res = handle_access_request(&uaddr);
    else {
      printf ("unhandled\n");
      continue;
    }

    if (res <= 0)
      continue;

    if (flag_dump) {
      if (uaddr.caddr.sa_family == AF_INET) {
	struct sockaddr_in *sin = (struct sockaddr_in *)&uaddr.caddr;
	printf ("### to: %s port %u, len: %u\n",
		inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), res);
      }
      dump_radius(uaddr.rep, res);
    }

    if (flag_write)
      write(bin_log, uaddr.rep, res);

    r = sendto (sock, uaddr.rep, res, 0, &uaddr.caddr, uaddr.caddr.sa_len);
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
    return dump_pcap();

  if (secret == NULL) {
    fprintf (stderr, "%s: missing secret option (-s SECRET)\n", progname);
    return 2;
  }

  return server(flag_write);
}
