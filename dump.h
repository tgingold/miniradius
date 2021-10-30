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

#ifndef _DUMP_H_
#define _DUMP_H_

/* Radius port.  */
extern unsigned port;

/* If true, dump only the EAP messages of radius packets.  */
extern unsigned dump_eap_only;

/* Read and dump pcap packets from stdin.  */
int dump_pcap(void);

/* Read and dump raw radius packets from stdin.  */
int dump_packets(void);

void dump_eap_message (const unsigned char *p, unsigned plen);
void dump_hex (const char *pfx, const unsigned char *p, unsigned len);
void dump_radius (const unsigned char *p, unsigned plen);
void dump_eap_response(const unsigned char *p, unsigned plen);
void dump_tls (const unsigned char *p, unsigned plen);

#endif /* _DUMP_H_ */
