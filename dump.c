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
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "radius.h"
#include "dump.h"

unsigned dump_eap_only = 0;

static uint16_t
read16 (const unsigned char *p)
{
  return (p[0] << 8) | p[1];
}

static uint32_t
read24 (const unsigned char *p)
{
  return (p[0] << 16) | (p[1] << 8) | p[2];
}

void
dump_hex (const char *pfx, const unsigned char *p, unsigned len)
{
  unsigned i, j;
  for (i = 0; i < len; i += 16) {
    printf ("%s%04x:", pfx, i);
    for (j = i; j < len && j < i + 16; j++)
      printf (" %02x", p[j]);
    putchar('\n');
  }
}

static const char *
disp_tls_content_type (unsigned c)
{
  switch (c) {
  case TLS_TYPE_CHANGE_CIPHER_SPEC:
    return "change_cipher_spec";
  case TLS_TYPE_ALERT:
    return "alert";
  case TLS_TYPE_HANDSHAKE:
    return "handshake";
  case TLS_TYPE_APPLICATION_DATA:
    return "application_data";
  default:
    return "??";
  }
}

/* TLS 1.2:
   https://datatracker.ietf.org/doc/html/rfc5246
*/
void
dump_tls (const unsigned char *p, unsigned plen)
{
  while (plen > 0) {
    unsigned len;
    unsigned char typ;

    if (plen < 4) {
      printf ("   ...truncated\n");
      break;
    }
    typ = p[0];
    printf ("   type: %u %s", typ, disp_tls_content_type (typ));
    printf (",  protocol version: %u.%u", p[1], p[2]);
    len = read16(p + 3);
    printf (",  len: %u\n", len);

    if (len + 5 > plen) {
      printf ("   ...(truncated)\n");
      break;
    }

    switch (typ) {
    case TLS_TYPE_CHANGE_CIPHER_SPEC:
      if (len != 1)
	printf ("    bad length\n");
      else
	printf ("    new spec: %u\n", p[5]);
      break;
    case TLS_TYPE_ALERT:
      if (len != 2)
	printf ("    bad length\n");
      else
	printf ("    level: %u, desc: %u\n", p[5], p[6]);
      break;
    case TLS_TYPE_HANDSHAKE: {
      unsigned blen;
      if (len < 4) {
	printf ("    bad length\n");
	break;
      }
      blen = read24(p + 6);
      printf ("    msg type: %u, len: %u  ", p[5], blen);
      switch (p[5]) {
      case TLS_HANDSHAKE_HELLO_REQUEST:
	printf ("hello request");
	break;
      case TLS_HANDSHAKE_CLIENT_HELLO:
	printf ("client_hello");
	break;
      case TLS_HANDSHAKE_SERVER_HELLO:
	printf ("server_hello");
	break;
      case TLS_HANDSHAKE_CERTIFICATE:
	printf ("certificate");
	break;
      case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
	printf ("server_key_exchange");
	break;
      case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
	printf ("certificate_request");
	break;
      case TLS_HANDSHAKE_SERVER_HELLO_DONE:
	printf ("server_hello_done");
	break;
      case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
	printf ("certificate_verify");
	break;
      case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
	printf ("client_key_exchange");
	break;
      case TLS_HANDSHAKE_FINISHED:
	printf ("finished");
	break;
      }
      if (blen != len - 4)
	printf (" [weird len]");
      putchar('\n');
      break;
    }
    default:
      break;
    }

    switch (p[5]) {
    case TLS_HANDSHAKE_CLIENT_HELLO:
      if (len < 47)
	break;
      {
      unsigned i;
      unsigned slen;
      unsigned off;
      off = 9;
      printf ("    client_version: %u.%u\n", p[off + 0], p[off + 1]);
      printf ("    random: ");
      off += 2;
      for (i = 0; i < 32; i++)
	printf ("%02x", p[off + i]);
      putchar('\n');
      off += 32; /* 43 */
      slen = p[off];
      off += 1;
      printf ("    session: ");
      for (i = 0; i < slen; i++)
	printf ("%02x", p[off + i]);
      putchar('\n');
      off += slen;
      slen = read16(p + off);
      off += 2;
      printf ("    cipher_suites:");
      for (i = 0; i < slen; i += 2) {
	printf (" 0x%04x", read16(p + off));
	off += 2;
      }
      putchar ('\n');
      off += 2;
      slen = p[off];
      printf ("    compression_methods:");
      for (i = 0; i < slen; i++) {
	printf (" 0x%02x", p[off]);
	off++;
      }
      putchar('\n');
    }
      break;
    case TLS_HANDSHAKE_SERVER_HELLO: {
      unsigned i;
      unsigned slen;
      unsigned off;
      off = 9;
      printf ("    server_version: %u.%u\n", p[off + 0], p[off + 1]);
      printf ("    random: ");
      off += 2;
      for (i = 0; i < 32; i++)
	printf ("%02x", p[off + i]);
      putchar('\n');
      off += 32; /* 43 */
      slen = p[off];
      off += 1;
      printf ("    session: ");
      for (i = 0; i < slen; i++)
	printf ("%02x", p[off + i]);
      putchar('\n');
      off += slen;
      printf ("    cipher_suite: 0x%04x\n", read16(p + off));
      off += 2;
      printf ("    compression_method: 0x%02x\n", p[off]);
    }
      break;
    }
    p += len + 5;
    plen -= len + 5;
  }
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
  if (p[0] & PEAP_FLAG_LEN)
    printf (" Len");
  if (p[0] & PEAP_FLAG_MORE)
    printf (" MoreFrag");
  if (p[0] & PEAP_FLAG_START)
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
  case EAP_TYPE_PEAP_EXTENSION:
    return "PEAP extension";
  case EAP_TYPE_PWD:
    return "pwd";
  default:
    return "??";
  }
}

void
dump_eap_response(const unsigned char *p, unsigned plen)
{
  printf ("  type: %u  %s\n", p[0], disp_eap_type(p[0]));
}

void
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
  case EAP_CODE_SUCCESS:
    printf ("Success");
    break;
  case EAP_CODE_FAILURE:
    printf ("Failure");
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
	break;
      case EAP_TYPE_PEAP_EXTENSION:
	if (len < 9) {
	  printf ("  Incorrect length\n");
	  break;
	}
	else {
	  unsigned avp_len = read16(p + 7);
	  printf ("   AVP type: %04x, len: %u\n", read16(p + 5), avp_len);
	  if (avp_len != len - 9)
	    printf ("   Bad AVP length\n");
	  else
	    dump_hex ("   ", p + 9, avp_len);
	}
	break;
      }
    }
    break;
  default:
    putchar('\n');
    break;
  }
}

void
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

int
dump_packets(void)
{
  unsigned char buf[4096];
  int len;
  int res;

  while (1) {
    len = read(0, buf, 4);
    if (len == 0)
      return 0;
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
  }

  return 0;
}

int
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
    if ((unsigned)len != plen) {
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
    if (read16(buf + hlen) == port)
      printf (" from server\n");
    else if (read16(buf + hlen + 2) == port)
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
