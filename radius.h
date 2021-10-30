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

#ifndef __RADIUS__H_
#define __RADIUS__H_

/* Radius (and more) definitions.  */

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
#define EAP_TYPE_PEAP_EXTENSION 33
#define EAP_TYPE_PWD 52  /* RFC 5931 */

#define EAP_ETYPE_RESULT 0x8003  /* MS-PEAP */
#define RESULT_SUCCESS 1
#define RESULT_FAILURE 2

#define PEAP_FLAG_MASK  0xe0
#define PEAP_FLAG_START 0x20
#define PEAP_FLAG_MORE  0x40
#define PEAP_FLAG_LEN   0x80

#define TLS_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_TYPE_ALERT 21
#define TLS_TYPE_HANDSHAKE 22
#define TLS_TYPE_APPLICATION_DATA 23

#define TLS_HANDSHAKE_HELLO_REQUEST 0
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_HANDSHAKE_CERTIFICATE 11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED 20

#endif /*  __RADIUS__H_ */
