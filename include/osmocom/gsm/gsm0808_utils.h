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
#pragma once

#include <sys/socket.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>

/* Encode AoIP transport address element */
struct msgb *gsm0808_enc_aoip_trasp_addr(struct sockaddr_storage *ss);

/* Decode AoIP transport address element */
struct sockaddr_storage *gsm0808_dec_aoip_trasp_addr(const void *ctx,
						     struct msgb *msg);

/* Encode Speech Codec element */
struct msgb *gsm0808_enc_speech_codec(struct gsm0808_speech_codec *sc);

/* Decode Speech Codec element */
struct gsm0808_speech_codec *gsm0808_dec_speech_codec(const void *ctx,
						      struct msgb *msg);

/* Encode Speech Codec list */
struct msgb *gsm0808_enc_speech_codec_list(struct llist_head *scl);

/* Decode Speech Codec list */
struct llist_head *gsm0808_dec_speech_codec_list(const void *ctx,
						 struct msgb *msg);

/* Encode Channel Type element */
struct msgb *gsm0808_enc_channel_type(struct gsm0808_channel_type *ct);

/* Decode Channel Type element */
struct gsm0808_channel_type *gsm0808_dec_channel_type(const void *ctx,
						      struct msgb *msg);