/* (C) 2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_V4_ADDR_LEN 4
#define IP_V6_ADDR_LEN 16
#define IP_PORT_LEN 2

/* Encode AoIP transport address element */
struct msgb *gsm0808_enc_aoip_trasp_addr(struct sockaddr_storage *ss)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;

	uint8_t *ptr;
	struct msgb *msg;

	OSMO_ASSERT(ss);
	OSMO_ASSERT(ss->ss_family == AF_INET || ss->ss_family == AF_INET6);

	msg = msgb_alloc(sizeof(*ss), "AoIP Transport Layer Address");
	if (!msg)
		return NULL;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		port = ntohs(sin->sin_port);
		ptr = msgb_put(msg, IP_V4_ADDR_LEN);
		memcpy(ptr, &sin->sin_addr.s_addr, IP_V4_ADDR_LEN);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		port = ntohs(sin6->sin6_port);
		ptr = msgb_put(msg, IP_V6_ADDR_LEN);
		memcpy(ptr, sin6->sin6_addr.s6_addr, IP_V6_ADDR_LEN);
		break;
	}

	msgb_put_u16(msg, port);
	return msg;
}

/* Decode AoIP transport address element */
struct sockaddr_storage *gsm0808_dec_aoip_trasp_addr(const void *ctx,
						     struct msgb *msg)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_storage *ss;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	OSMO_ASSERT(msg);

	switch (msg->len) {

	case IP_V4_ADDR_LEN + IP_PORT_LEN:
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(msgb_get_u16(msg));
		memcpy(&sin.sin_addr.s_addr, msg->data, IP_V4_ADDR_LEN);
		ss = talloc_zero(ctx, struct sockaddr_storage);
		if (!ss)
			return NULL;
		memcpy(ss, &sin, sizeof(sin));
		break;
	case IP_V6_ADDR_LEN + IP_PORT_LEN:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(msgb_get_u16(msg));
		memcpy(sin6.sin6_addr.s6_addr, msg->data, IP_V6_ADDR_LEN);
		ss = talloc_zero(ctx, struct sockaddr_storage);
		if (!ss)
			return NULL;
		memcpy(ss, &sin6, sizeof(sin6));
		break;
	default:
		/* Malformed element */
		return NULL;
		break;
	}

	return ss;
}
