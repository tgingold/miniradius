#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hmac_md5.h"
#include "md5.h"

static unsigned port = 1812;
static unsigned dump_eap_only = 1;

/* Radius: RFC 2865
   https://www.rfc-editor.org/rfc/rfc2865

   EAP extensions (with examples of conversation):
   https://www.rfc-editor.org/rfc/rfc3579

   802.1x:
   https://www.rfc-editor.org/rfc/rfc3580

   EAP:
   https://www.rfc-editor.org/rfc/rfc2284

   OTP:
   https://www.rfc-editor.org/rfc/rfc1938
*/

/* Radius codes:  */
#define CODE_ACCESS_REQUEST 1
#define CODE_ACCESS_ACCEPT 2
#define CODE_ACCESS_REJECT 3
#define CODE_ACCESS_CHALLENGE 11

/* Radius attributes.
   https://www.iana.org/assignments/radius-types/radius-types.xhtml
*/
#define ATTR_USER_NAME  1
#define ATTR_USER_PASSWORD 2
#define ATTR_CHAP_PASSWORD 3
#define ATTR_NAS_IP_ADDRESS 4
#define ATTR_NAS_PORT 5
#define ATTR_SERVICE_TYPE 6
#define ATTR_FRAMED_PROTOCOL 7
#define ATTR_FRAMED_IP_ADDRESS 8
#define ATTR_FRAMED_IP_NETMASK 9
#define ATTR_FRAMED_ROUTING 10
#define ATTR_FILTER_ID 11
#define ATTR_FRAMED_MTU 12
#define ATTR_FRAMED_COMPRESSION 13
#define ATTR_LOGIN_IP_HOST 14
#define ATTR_LOGIN_SERVICE 15
#define ATTR_LOGIN_TCP_PORT 16
#define ATTR_REPLY_MESSAGE 18
#define ATTR_CALLBACK_NUMBER 19
#define ATTR_CALLBACK_ID 20
#define ATTR_FRAMED_ROUTE 22
#define ATTR_FRAMED_IPX_NETWORK 23
#define ATTR_STATE 24
#define ATTR_CLASS 25
#define ATTR_VENDOR_SPECIFIC 26
#define ATTR_SESSION_TIMEOUT 27
#define ATTR_IDLE_TIMEOUT 28
#define ATTR_TERMINATION_ACTION 29
#define ATTR_CALLED_STATION_ID 30
#define ATTR_CALLING_STATION_ID 31
#define ATTR_NAS_IDENTIFIER 32
#define ATTR_PROXY_STATE 33
#define ATTR_LOGIN_LAT_SERVICE 34
#define ATTR_LOGIN_LAT_NODE 35
#define ATTR_LOGIN_LAT_GROUP 36
#define ATTR_FRAMED_APPLETALK_LINK 37
#define ATTR_FRAMED_APPLETALK_NETWORK 38
#define ATTR_FRAMED_APPLETALK_ZONE 39
#define ATTR_CHAP_CHALLENGE 60
#define ATTR_NAS_PORT_TYPE 61
#define ATTR_PORT_LIMIT 62
#define ATTR_LOGIN_LAT_PORT 63
#define ATTR_CONNECT_INFO 77
#define ATTR_EAP_MESSAGE 79
#define ATTR_MESSAGE_AUTHENTICATOR 80

/* EAP Code  */
#define EAP_CODE_REQUEST 1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS 3
#define EAP_CODE_FAILURE 4

#define EAP_TYPE_IDENTITY 1
#define EAP_TYPE_NOTIFICATION 2
#define EAP_TYPE_NAK 3
#define EAP_TYPE_MD5_CHALLENGE 4
#define EAP_TYPE_OTP 5
#define EAP_TYPE_GTC 6
#define EAP_TYPE_EAP_TLS 13
#define EAP_TYPE_EAP_TTLS 0x15
#define EAP_TYPE_PEAP 0x19
#define EAP_TYPE_PEAPv0 33
#define EAP_TYPE_PWD 52  /* RFC 5931 */

static unsigned char key[] = "pass";
static unsigned key_len = sizeof(key) - 1;

static const char *
disp_tls_content_type (unsigned c)
{
  switch (c) {
  case 20:
    return "change_cipher_spec";
  case 21:
    return "alert";
  case 22:
    return "handshake";
  case 23:
    return "application_data";
  default:
    return "??";
  }
}

/* TLS 1.2:
   https://datatracker.ietf.org/doc/html/rfc5246
*/
static void
dump_tls (const unsigned char *p, unsigned plen)
{
  unsigned len;
  printf ("   type: %02x %s", p[0], disp_tls_content_type (p[0]));
  printf (",  protocol version: %u.%u", p[1], p[2]);
  len = (p[3] << 8) | p[4];
  printf (",  len: %u\n", len);
}

/* See:
   https://tools.ietf.org/id/draft-josefsson-pppext-eap-tls-eap-06.txt
*/
static void
dump_peap (const unsigned char *p, unsigned plen)
{
  unsigned len;
  unsigned hlen;

  hlen = 1;
  printf ("   flags: %02x", p[0]);
  if (p[0] & 0x80)
    printf (" Len");
  if (p[0] & 0x40)
    printf (" MoreFrag");
  if (p[0] & 0x20)
    printf (" PEAP-Start");
  if (p[0] & 0x18)
    printf (" MBZ-Err");
  printf (", ver: %u", p[0] & 0x7);
  if (p[0] & 0x80) {
    len = (p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4];
    printf (",  len=%u", len);
    hlen += 4;
  }
  putchar('\n');
  if (plen > hlen)
    dump_tls (p + hlen, plen - hlen);
}

static const char *
disp_eap_type (unsigned char typ)
{
  switch (typ) {
  case EAP_TYPE_IDENTITY:
    return "identity";
  case EAP_TYPE_NOTIFICATION:
    return "notification";
  case EAP_TYPE_NAK:
    return "Nak";
  case EAP_TYPE_MD5_CHALLENGE:
    return "MD5-Challenge";
  case EAP_TYPE_OTP:
    return "One-Time Password (OTP)";
  case EAP_TYPE_GTC:
    return "Generic Token Card";
  case EAP_TYPE_EAP_TLS:
    return "EAP-TLS";
  case EAP_TYPE_EAP_TTLS:
    return "EAP-TTLS";
  case EAP_TYPE_PEAP:
    return "PEAP";
  case EAP_TYPE_PEAPv0:
    return "PEAPv0";
  case EAP_TYPE_PWD:
    return "pwd";
  default:
    return "??";
  }
}

static void
dump_eap_message (const unsigned char *p, unsigned plen)
{
  unsigned len = (p[2] << 8) | p[3];

  printf ("  code: %u, ident: %02x, len: %u  ", p[0], p[1], len);
  switch (p[0]) {
  case EAP_CODE_REQUEST:
    printf ("Request");
    break;
  case EAP_CODE_RESPONSE:
    printf ("Response");
    break;
  }
  if (len != plen) {
    putchar ('\n');
    printf ("  Incorrect length\n");
    return;
  }

  switch (p[0]) {
  case EAP_CODE_REQUEST:
  case EAP_CODE_RESPONSE:
    {
      if (len <= 4) {
	printf (" Incorrect length\n");
	break;
      }
      printf ("  type: %u  %s\n", p[4], disp_eap_type(p[4]));
      switch (p[4]) {
      case EAP_TYPE_PEAP:
	dump_peap (p + 5, len - 5);
	break;
      case EAP_TYPE_NAK:
	{
	  unsigned i;
	  printf ("   desired types:");
	  for (i = 5; i < len; i++)
	    printf ("  %02x (%s)", p[i], disp_eap_type(p[i]));
	  putchar('\n');
	}
      }
    }
    break;
  default:
    putchar('\n');
    break;
  }
}

  static void
dump_radius (const unsigned char *p, unsigned plen)
{
  unsigned char eap_buf[4096];
  unsigned eap_len = 0;
  unsigned len;
  unsigned off;
  unsigned i;

  /* Minimum length is 20, max is 4096.  */
  if (plen < 20) {
    printf ("packet is too short\n");
    return;
  }

  len = (p[2] << 8) | p[3];
  printf ("code: %u, identifier: %u, len: %u  ", p[0], p[1], len);

  switch(p[0]) {
  case CODE_ACCESS_REQUEST:
    printf ("Access-Request");
    break;
  case CODE_ACCESS_ACCEPT:
    printf ("Access-Accept");
    break;
  case CODE_ACCESS_REJECT:
    printf ("Access-Reject");
    break;
  case CODE_ACCESS_CHALLENGE:
    printf ("Access-Challenge");
    break;
  default:
    printf ("??");
    break;
  }
  printf ("\n");

  if (len < 20 || len > 4096) {
    printf ("Bad length: out of bounds\n");
    return;
  }
  if (len > plen) {
    printf ("Bad length: packet truncated\n");
    return;
  }
  if (len < plen) {
    printf ("Weird length: packet padded\n");
    return;
  }

  if (!dump_eap_only) {
    printf ("Authenticator:");
    for (i = 0; i < 16; i++)
      printf (" %02x", p[4 + i]);
    printf ("\n");
  }

  for (off = 20; off < plen; ) {
    unsigned atype;
    unsigned alen;

    if (off + 3 >= plen) {
      printf ("truncated attribute\n");
      return;
    }
    atype = p[off];
    alen = p[off + 1];

    if (!dump_eap_only) {
      printf ("attribute: %u, len: %u  ", atype, alen);

      switch (atype)
	{
	case ATTR_USER_NAME:
	  printf("User-Name");
	  break;
	case ATTR_USER_PASSWORD:
	  printf("User-Password");
	  break;
	case ATTR_CHAP_PASSWORD:
	  printf("CHAP-Password");
	  break;
	case ATTR_NAS_IP_ADDRESS:
	  printf("NAS-IP-Address");
	  break;
	case ATTR_NAS_PORT:
	  printf("NAS-Port");
	  break;
	case ATTR_SERVICE_TYPE:
	  printf("Service-Type");
	  break;
	case ATTR_FRAMED_PROTOCOL:
	  printf("Framed-Protocol");
	  break;
	case ATTR_FRAMED_IP_ADDRESS:
	  printf("Framed-IP-Address");
	  break;
	case ATTR_FRAMED_IP_NETMASK:
	  printf("Framed-IP-Netmask");
	  break;
	case ATTR_FRAMED_ROUTING:
	  printf("Framed-Routing");
	  break;
	case ATTR_FILTER_ID:
	  printf("Filter-Id");
	  break;
	case ATTR_FRAMED_MTU:
	  printf("Framed-MTU");
	  break;
	case ATTR_FRAMED_COMPRESSION:
	  printf("Framed-Compression");
	  break;
	case ATTR_LOGIN_IP_HOST:
	  printf("Login-IP-Host");
	  break;
	case ATTR_LOGIN_SERVICE:
	  printf("Login-Service");
	  break;
	case ATTR_LOGIN_TCP_PORT:
	  printf("Login-TCP-Port");
	  break;
	case ATTR_REPLY_MESSAGE:
	  printf("Reply-Message");
	  break;
	case ATTR_CALLBACK_NUMBER:
	  printf("Callback-Number");
	  break;
	case ATTR_CALLBACK_ID:
	  printf("Callback-Id");
	  break;
	case ATTR_FRAMED_ROUTE:
	  printf("Framed-Route");
	  break;
	case ATTR_FRAMED_IPX_NETWORK:
	  printf("Framed-IPX-Network");
	  break;
	case ATTR_STATE:
	  printf("State");
	  break;
	case ATTR_CLASS:
	  printf("Class");
	  break;
	case ATTR_VENDOR_SPECIFIC:
	  printf("Vendor-Specific");
	  break;
	case ATTR_SESSION_TIMEOUT:
	  printf("Session-Timeout");
	  break;
	case ATTR_IDLE_TIMEOUT:
	  printf("Idle-Timeout");
	  break;
	case ATTR_TERMINATION_ACTION:
	  printf("Termination-Action");
	  break;
	case ATTR_CALLED_STATION_ID:
	  printf("Called-Station-Id");
	  break;
	case ATTR_CALLING_STATION_ID:
	  printf("Calling-Station-Id");
	  break;
	case ATTR_NAS_IDENTIFIER:
	  printf("NAS-Identifier");
	  break;
	case ATTR_PROXY_STATE:
	  printf("Proxy-State");
	  break;
	case ATTR_LOGIN_LAT_SERVICE:
	  printf("Login-LAT-Service");
	  break;
	case ATTR_LOGIN_LAT_NODE:
	  printf("Login-LAT-Node");
	  break;
	case ATTR_LOGIN_LAT_GROUP:
	  printf("Login-LAT-Group");
	  break;
	case ATTR_FRAMED_APPLETALK_LINK:
	  printf("Framed-AppleTalk-Link");
	  break;
	case ATTR_FRAMED_APPLETALK_NETWORK:
	  printf("Framed-AppleTalk-Network");
	  break;
	case ATTR_FRAMED_APPLETALK_ZONE:
	  printf("Framed-AppleTalk-Zone");
	  break;
	case ATTR_CHAP_CHALLENGE:
	  printf("CHAP-Challenge");
	  break;
	case ATTR_NAS_PORT_TYPE:
	  printf("NAS-Port-Type");
	  break;
	case ATTR_PORT_LIMIT:
	  printf("Port-Limit");
	  break;
	case ATTR_LOGIN_LAT_PORT:
	  printf("Login-LAT-Port");
	  break;
	case ATTR_CONNECT_INFO:
	  printf("Connect-Info");
	  break;
	case ATTR_EAP_MESSAGE:
	  printf("EAP-Message");
	  break;
	case ATTR_MESSAGE_AUTHENTICATOR:
	  printf("Message-Authenticator");
	  break;
	default:
	  printf ("??");
	}
    }
    if (alen < 3 || off + alen > plen) {
      printf (" - bad attribute length\n");
      return;
    }

    if (!dump_eap_only) {
      printf ("\n");
      printf (" value:");
      for (i = 2; i < alen; i++)
	printf (" %02x", p[off + i]);
      printf ("\n");
      printf (" ascii: ");
      for (i = 2; i < alen; i++) {
	unsigned c = p[off + i];
	if (c < ' ' || c >= 127)
	  c = '.';
	putchar(c);
      }
      printf ("\n");
    }

    if (atype == ATTR_EAP_MESSAGE) {
      if (alen < 6)
	printf ("  Bad EAP message length\n");
      else {
	memcpy (eap_buf + eap_len, p + off + 2, alen - 2);
	eap_len += alen - 2;
      }
    }
    off += alen;
  }

  if (eap_len != 0) {
    printf ("EAP message:\n");
    dump_eap_message(eap_buf, eap_len);
  }
}

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

      hmac_md5(p, plen, key, key_len, computed_digest);
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


static unsigned int
compute_eap_authenticator_noalloc (unsigned char *rep, unsigned int len,
				   unsigned char *p_mac)
{
  struct MD5Context md5_ctxt;

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
  hmac_md5(rep, len, key, key_len, p_mac);

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
  MD5Init (&md5_ctxt);
  MD5Update (&md5_ctxt, rep, len);
  MD5Update (&md5_ctxt, key, key_len);
  MD5Final (rep + 4, &md5_ctxt);

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

static int
do_eap_challenge(unsigned char *req, int rea_len,
		 unsigned char *eap, int eap_len,
		 unsigned char *rep)
{
  unsigned char *r;
  unsigned len;
  unsigned char *p_mac;

  /* Header.  */
  rep[0] = CODE_ACCESS_CHALLENGE;
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
    r[7] = 0x20; /* start */
    r[5] = 4 + 2;
  }
  else if (0) {
    r[6] = EAP_TYPE_EAP_TTLS;
    r[7] = 0x20;  /* start */
    r[5] = 4 + 2;
  }
  else if (1) {
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
handle_eap_message(unsigned char *p, int plen, unsigned eap_off,
		   unsigned char *rep)
{
  unsigned char *eap = p + eap_off + 2;
  unsigned eap_len = p[eap_off + 1];

  /* Sanity check.  */
  if (eap_len < 4) {
    printf ("Bad EAP-Message packet length\n");
    return -1;
  }

  /* Length of the EAP-Message string.  */
  eap_len -= 2;

  if (((eap[2] << 8) | eap[3]) != eap_len) {
    printf ("Bad EAP-Message length field\n");
    return -1;
  }

  if (eap[0] == EAP_CODE_RESPONSE) {
    if (eap_len < 5)
      return -1;

    switch (eap[4]) {
    case EAP_TYPE_IDENTITY:
      /* This is the first message: the identity has been transmitted,
	 time to challenge.  */
      return do_eap_challenge(p, plen, eap, eap_len, rep);
    case EAP_TYPE_MD5_CHALLENGE:
      return do_eap_auth(p, plen, eap, eap_len, rep);
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
handle_access_request(unsigned char *p, int plen, unsigned char *rep)
{
  int auth;
  unsigned off;

  auth = auth_request(p, plen);
  if (auth < 0) {
    printf ("Authentification failed\n");
    return -1;
  }
  else if (auth == 0) {
    printf ("Non authentified packet\n");
    return -1;
  }

  /* Find EAP-Message.
     TODO: gather EAP-Message attributes.  */
  for (off = 20; off < plen; ) {
    if (p[off] == ATTR_EAP_MESSAGE) {
      return handle_eap_message(p, plen, off, rep);
    }
    off += p[off + 1];
  }

  /* TODO: handle non EAP.  */
  printf ("Not handled: non-EAP request\n");
  return -1;
}

static int
server(void)
{
  int sock;
  struct sockaddr_in myaddr;
  int bin_log;

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

  bin_log = open("miniradius.pkt", O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (bin_log < 0)
    perror("cannot open log file");

  while (1) {
    struct sockaddr_in addr;
    unsigned char req[4096];
    unsigned char rep[4096];
    socklen_t alen = sizeof(addr);
    unsigned plen;
    int res;
    int r;

    r = recvfrom(sock, req, sizeof req, 0, (struct sockaddr *)&addr, &alen);
    if (r < 0) {
      if (errno == EAGAIN)
	continue;
      perror("cannot receive from socket");
      return 1;
    }

    if (alen >= sizeof(addr) && addr.sin_family == AF_INET) {
      printf ("### from: %s port %u, len: %u\n",
	      inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), r);
    }
    dump_radius(req, r);

    /* Discard invalid packets.  */
    if (r < 20 || r > 4096)
      continue;
    plen = (req[2] << 8) | req[3];
    if (plen < 20 || plen > r)
      continue;

    if (bin_log >= 0)
      write(bin_log, req, plen);

    /* TODO: check attributes (length)  */

    if (req[0] == CODE_ACCESS_REQUEST)
      res = handle_access_request(req, plen, rep);
    else {
      printf ("unhandled\n");
      continue;
    }

    if (res <= 0)
      continue;

    if (alen >= sizeof(addr) && addr.sin_family == AF_INET) {
      printf ("### to: %s port %u, len: %u\n",
	      inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), res);
    }
    dump_radius(rep, res);
    if (bin_log >= 0)
      write(bin_log, rep, res);

    r = sendto (sock, rep, res, 0, (struct sockaddr *)&addr, alen);
    if (r != res)
      perror ("sendto");
  }
}

static int
test_server(void)
{
  unsigned char buf[4096];
  unsigned char rep[4096];
  int len;
  int res;

  while (1) {
    len = read(0, buf, 4);
    if (len != 4) {
      perror ("read");
      return 1;
    }

    len = (buf[2] << 8) | buf[3];
    res = read(0, buf + 4, len - 4);
    if (res != len - 4) {
      perror ("read");
      return 1;
    }

    printf ("## Read %u bytes ########\n", len);
    dump_radius(buf, len);

    if (buf[0] == CODE_ACCESS_REQUEST)
      res = handle_access_request(buf, len, rep);
    else
      res = 0;

    if (res > 0) {
      printf ("## Write %u bytes ########\n", res);
      dump_radius(rep, res);
      //    write(1, rep, res);
    }
  }

  return 0;
}

static int
dump_pcap(void)
{
  unsigned char buf[4096];
  int len;

  len = read(0, buf, 24);
  if (len != 24) {
    perror ("read hdr");
    return 1;
  }
  if (buf[3] != 0xa1 || buf[2] != 0xb2 || buf[1] != 0xc3 || buf[0] != 0xd4) {
    printf ("Bad pcap magic\n");
    return 1;
  }

  while (1) {
    unsigned plen;
    unsigned flen;
    unsigned hlen;
    unsigned char *p;

    /* Read per-packet header.  */
    len = read(0, buf, 16);
    if (len == 0)
      return 0;
    if (len != 16) {
      perror ("read phdr");
      return 1;
    }
    plen = buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24);
    flen = buf[12] | (buf[13] << 8) | (buf[14] << 16) | (buf[15] << 24);

    len = read(0, buf, plen);
    if (len != plen) {
      perror("read pkt");
      return 1;
    }

    hlen = 6 + 6 + 2 + 20 + 8;  /* mac, ip, udp.  */

    printf ("## packet len=%u", plen);
    if (0) {
      p = buf;
      unsigned i, j;
      for (i = 0; i < plen; i += 16) {
	printf ("%04x:", i);
	for (j = i; j < plen && j < i + 16; j++)
	  printf (" %02x", p[j]);
	putchar('\n');
      }
    }

    if (plen < hlen) {
      printf (" truncated\n");
      continue;
    }
    if (buf[12] != 0x08 || buf[13] != 0x00) {
      printf (" not IP\n");
      continue;
    }
    if ((buf[14] & 0xf0) != 0x40
	|| (buf[14] & 0x0f) < 5) {
      printf (" not IPv4\n");
      continue;
    }

    hlen = 14;
    if (buf[hlen + 9] != 0x11) {
      printf (" not UDP\n");
      continue;
    }

    hlen += 4 * (buf[hlen] & 0x0f);
    if (((buf[hlen + 0] << 8) | buf[hlen + 1]) == port)
      printf (" from server\n");
    else if (((buf[hlen + 2] << 8) | buf[hlen + 3]) == port)
      printf (" to server\n");
    else {
      printf (" not radius port (hlen=%u, port=%04x)\n", hlen, port);
      continue;
    }

    hlen += 8;
    p = buf + hlen;
    plen -= hlen;

    dump_radius(p, plen);
  }
}

int
main (int argc, char *argv[])
{
  if (argc == 2 && strcmp(argv[1], "-") == 0)
    return test_server();
  else if (argc == 2 && strcmp(argv[1], "-r") == 0)
    return dump_pcap();
  else
    return server();
}


// ZhAXDptRAUGNPa86ZhZL3Jjdz1lDXay031fHddv17vz0Tw3P40tqQDFNsnYy8Lr
