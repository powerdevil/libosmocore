/*
 * (C) 2012 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERIFY(msg, data, len) 						\
	if (msgb_l3len(msg) != len) {					\
		printf("%s:%d Length don't match: %d vs. %d. %s\n", 	\
			__func__, __LINE__, msgb_l3len(msg), (int) len,	\
			osmo_hexdump(msg->l3h, msgb_l3len(msg))); 	\
		abort();						\
	} else if (memcmp(msg->l3h, data, len) != 0) {			\
		printf("%s:%d didn't match: got: %s\n",			\
			__func__, __LINE__,				\
			osmo_hexdump(msg->l3h, msgb_l3len(msg)));	\
		abort();						\
	}

/* Setup a fake codec list for testing */
static struct llist_head *setup_codec_list(const void *ctx)
{
	struct gsm0808_speech_codec *enc_sc1;
	struct gsm0808_speech_codec *enc_sc2;
	struct gsm0808_speech_codec *enc_sc3;

	struct llist_head *sc_list;

	sc_list = talloc_zero(ctx, struct llist_head);
	enc_sc1 = talloc_zero(sc_list, struct gsm0808_speech_codec);
	enc_sc2 = talloc_zero(sc_list, struct gsm0808_speech_codec);
	enc_sc3 = talloc_zero(sc_list, struct gsm0808_speech_codec);

	INIT_LLIST_HEAD(sc_list);

	memset(enc_sc1, 0, sizeof(*enc_sc1));
	enc_sc1->pi = true;
	enc_sc1->tf = true;
	enc_sc1->type = 0xab;
	enc_sc1->type_extended = true;
	enc_sc1->cfg_present = true;
	enc_sc1->cfg = 0xcdef;

	memset(enc_sc2, 0, sizeof(*enc_sc2));
	enc_sc2->fi = true;
	enc_sc2->pt = true;
	enc_sc2->type = 0x05;

	memset(enc_sc3, 0, sizeof(*enc_sc3));
	enc_sc3->fi = true;
	enc_sc3->tf = true;
	enc_sc3->type = 0xf2;
	enc_sc3->type_extended = true;

	llist_add(&enc_sc3->list, sc_list);
	llist_add(&enc_sc2->list, sc_list);
	llist_add(&enc_sc1->list, sc_list);

	return sc_list;
}

static void test_create_layer3(void)
{
	static const uint8_t res[] = {
		0x00, 0x0e, 0x57, 0x05, 0x08, 0x00, 0x77, 0x62,
		0x83, 0x33, 0x66, 0x44, 0x88, 0x17, 0x01, 0x23 };
	struct msgb *msg, *in_msg;
	printf("Testing creating Layer3\n");

	in_msg = msgb_alloc_headroom(512, 128, "foo");
	in_msg->l3h = in_msg->data;
	msgb_v_put(in_msg, 0x23);

	msg = gsm0808_create_layer3(in_msg, 0x1122, 0x2244, 0x3366, 0x4488);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
	msgb_free(in_msg);
}

static void test_create_layer3_aoip(const void *ctx)
{
	static const uint8_t res[] = {
		0x00, 0x17, 0x57, 0x05, 0x08, 0x00, 0x77, 0x62,
		0x83, 0x33, 0x66, 0x44, 0x88, 0x17, 0x01, 0x23,
		    GSM0808_IE_SPEECH_CODEC_LIST, 0x07, 0x5f, 0xab, 0xcd, 0xef,
		    0xa5, 0x9f, 0xf2
	};

	struct msgb *msg, *in_msg;
	struct llist_head *sc_list;
	printf("Testing creating Layer3 (AoIP)\n");

	sc_list = setup_codec_list(ctx);

	in_msg = msgb_alloc_headroom(512, 128, "foo");
	in_msg->l3h = in_msg->data;
	msgb_v_put(in_msg, 0x23);

	msg =
	    gsm0808_create_layer3_aoip(in_msg, 0x1122, 0x2244, 0x3366, 0x4488,
				       sc_list);
	VERIFY(msg, res, ARRAY_SIZE(res));
	talloc_free(sc_list);
	msgb_free(msg);
	msgb_free(in_msg);
}

static void test_create_reset()
{
	static const uint8_t res[] = { 0x00, 0x04, 0x30, 0x04, 0x01, 0x20 };
	struct msgb *msg;

	printf("Testing creating Reset\n");
	msg = gsm0808_create_reset();
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_clear_command()
{
	static const uint8_t res[] = { 0x20, 0x04, 0x01, 0x23 };
	struct msgb *msg;

	printf("Testing creating Clear Command\n");
	msg = gsm0808_create_clear_command(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_clear_complete()
{
	static const uint8_t res[] = { 0x00, 0x01, 0x21 };
	struct msgb *msg;

	printf("Testing creating Clear Complete\n");
	msg = gsm0808_create_clear_complete();
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_cipher_complete()
{
	static const uint8_t res1[] = {
		0x00, 0x08, 0x55, 0x20, 0x03, 0x23, 0x42, 0x21, 0x2c, 0x04 };
	static const uint8_t res2[] = { 0x00, 0x03, 0x55, 0x2c, 0x04};
	struct msgb *l3, *msg;

	printf("Testing creating Cipher Complete\n");
	l3 = msgb_alloc_headroom(512, 128, "l3h");
	l3->l3h = l3->data;
	msgb_v_put(l3, 0x23);
	msgb_v_put(l3, 0x42);
	msgb_v_put(l3, 0x21);

	/* with l3 data */
	msg = gsm0808_create_cipher_complete(l3, 4);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	/* with l3 data but short */
	l3->len -= 1;
	l3->tail -= 1;
	msg = gsm0808_create_cipher_complete(l3, 4);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);

	/* without l3 data */
	msg = gsm0808_create_cipher_complete(NULL, 4);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);


	msgb_free(l3);
}

static void test_create_cipher_reject()
{
	static const uint8_t res[] = { 0x00, 0x02, 0x59, 0x23 };
	struct msgb *msg;

	printf("Testing creating Cipher Reject\n");
	msg = gsm0808_create_cipher_reject(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_cm_u()
{
	static const uint8_t res[] = {
		0x00, 0x07, 0x54, 0x12, 0x01, 0x23, 0x13, 0x01, 0x42 };
	static const uint8_t res2o[] = {
		0x00, 0x04, 0x54, 0x12, 0x01, 0x23 };
	struct msgb *msg;
	const uint8_t cm2 = 0x23;
	const uint8_t cm3 = 0x42;

	printf("Testing creating CM U\n");
	msg = gsm0808_create_classmark_update(&cm2, 1, &cm3, 1);
	VERIFY(msg, res, ARRAY_SIZE(res));

	msg = gsm0808_create_classmark_update(&cm2, 1, NULL, 0);
	VERIFY(msg, res2o, ARRAY_SIZE(res2o));

	msgb_free(msg);
}

static void test_create_sapi_reject()
{
	static const uint8_t res[] = { 0x00, 0x03, 0x25, 0x03, 0x25 };
	struct msgb *msg;

	printf("Testing creating SAPI Reject\n");
	msg = gsm0808_create_sapi_reject(3);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_ass_compl()
{
	static const uint8_t res1[] = {
		0x00, 0x09, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c,
		0x11, 0x40, 0x22 };
	static const uint8_t res2[] = {
		0x00, 0x07, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c, 0x11};
	struct msgb *msg;

	printf("Testing creating Assignment Complete\n");
	msg = gsm0808_create_assignment_completed(0x23, 0x42, 0x11, 0x22);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_assignment_completed(0x23, 0x42, 0x11, 0);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_ass_compl_aoip(const void *ctx)
{
	struct sockaddr_storage ss;
	struct sockaddr_in sin;
	struct gsm0808_speech_codec sc;
	struct llist_head *sc_list;
	static const uint8_t res[] =
	    { 0x00, 0x1d, 0x02, 0x15, 0x23, 0x21, 0x42, 0x2c, 0x11, 0x40, 0x22,
	      GSM0808_IE_AOIP_TRASP_ADDR, 0x06, 0xc0, 0xa8, 0x64, 0x17, 0x04,
	      0xd2, GSM0808_IE_SPEECH_CODEC, 0x01, 0x9a,
	      GSM0808_IE_SPEECH_CODEC_LIST, 0x07, 0x5f, 0xab, 0xcd, 0xef, 0xa5,
	      0x9f, 0xf2 };
	struct msgb *msg;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(1234);
	inet_aton("192.168.100.23", &sin.sin_addr);

	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, &sin, sizeof(sin));

	memset(&sc, 0, sizeof(sc));
	sc.fi = true;
	sc.tf = true;
	sc.type = 0x0a;

	sc_list = setup_codec_list(ctx);

	printf("Testing creating Assignment Complete (AoIP)\n");
	msg =
	    gsm0808_create_assignment_completed_aoip(0x23, 0x42, 0x11, 0x22,
						     &ss, &sc, sc_list);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
	talloc_free(sc_list);
}

static void test_create_ass_fail()
{
	static const uint8_t res1[] = { 0x00, 0x04, 0x03, 0x04, 0x01, 0x23 };
	static const uint8_t res2[] = {
		0x00, 0x06, 0x03, 0x04, 0x01, 0x23, 0x15, 0x02};
	uint8_t rr_res = 2;
	struct msgb *msg;

	printf("Testing creating Assignment Failure\n");
	msg = gsm0808_create_assignment_failure(0x23, NULL);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_assignment_failure(0x23, &rr_res);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
}

static void test_create_ass_fail_aoip(const void *ctx)
{
	static const uint8_t res1[] =
	    { 0x00, 0x0d, 0x03, 0x04, 0x01, 0x23, GSM0808_IE_SPEECH_CODEC_LIST,
		0x07, 0x5f, 0xab, 0xcd, 0xef, 0xa5, 0x9f, 0xf2 };
	static const uint8_t res2[] =
	    { 0x00, 0x0f, 0x03, 0x04, 0x01, 0x23, 0x15, 0x02,
		GSM0808_IE_SPEECH_CODEC_LIST, 0x07, 0x5f, 0xab,
		0xcd, 0xef, 0xa5, 0x9f, 0xf2 };
	uint8_t rr_res = 2;
	struct msgb *msg;
	struct llist_head *sc_list;

	sc_list = setup_codec_list(ctx);

	printf("Testing creating Assignment Failure (AoIP)\n");
	msg = gsm0808_create_assignment_failure_aoip(0x23, NULL, sc_list);
	VERIFY(msg, res1, ARRAY_SIZE(res1));
	msgb_free(msg);

	msg = gsm0808_create_assignment_failure_aoip(0x23, &rr_res, sc_list);
	VERIFY(msg, res2, ARRAY_SIZE(res2));
	msgb_free(msg);
	talloc_free(sc_list);
}

static void test_create_clear_rqst()
{
	static const uint8_t res[] = { 0x00, 0x04, 0x22, 0x04, 0x01, 0x23 };
	struct msgb *msg;

	printf("Testing creating Clear Request\n");
	msg = gsm0808_create_clear_rqst(0x23);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
}

static void test_create_dtap()
{
	static const uint8_t res[] = { 0x01, 0x03, 0x02, 0x23, 0x42 };
	struct msgb *msg, *l3;

	printf("Testing creating DTAP\n");
	l3 = msgb_alloc_headroom(512, 128, "test");
	l3->l3h = l3->data;
	msgb_v_put(l3, 0x23);
	msgb_v_put(l3, 0x42);

	msg = gsm0808_create_dtap(l3, 0x3);
	VERIFY(msg, res, ARRAY_SIZE(res));
	msgb_free(msg);
	msgb_free(l3);
}

static void test_prepend_dtap()
{
	static const uint8_t res[] = { 0x01, 0x03, 0x02, 0x23, 0x42 };
	struct msgb *in_msg;

	printf("Testing prepend DTAP\n");

	in_msg = msgb_alloc_headroom(512, 128, "test");
	msgb_v_put(in_msg, 0x23);
	msgb_v_put(in_msg, 0x42);

	gsm0808_prepend_dtap_header(in_msg, 0x3);
	in_msg->l3h = in_msg->data;
	VERIFY(in_msg, res, ARRAY_SIZE(res));
	msgb_free(in_msg);
}

static void test_enc_dec_aoip_trasp_addr_v4(const void *ctx)
{
	struct sockaddr_storage enc_addr;
	struct sockaddr_storage *dec_addr;
	struct sockaddr_in enc_addr_in;
	struct msgb *msg;

	memset(&enc_addr_in, 0, sizeof(enc_addr_in));
	enc_addr_in.sin_family = AF_INET;
	enc_addr_in.sin_port = htons(1234);
	inet_aton("255.0.255.255", &enc_addr_in.sin_addr);

	memset(&enc_addr, 0, sizeof(enc_addr));
	memcpy(&enc_addr, &enc_addr_in, sizeof(enc_addr_in));

	msg = gsm0808_enc_aoip_trasp_addr(&enc_addr);
	OSMO_ASSERT(msg);
	dec_addr = gsm0808_dec_aoip_trasp_addr(ctx, msg);

	OSMO_ASSERT(memcmp(&enc_addr, dec_addr, sizeof(enc_addr)) == 0);

	talloc_free(dec_addr);
	msgb_free(msg);
}

static void test_enc_dec_aoip_trasp_addr_v6(const void *ctx)
{
	struct sockaddr_storage enc_addr;
	struct sockaddr_storage *dec_addr;
	struct sockaddr_in6 enc_addr_in;
	struct msgb *msg;

	memset(&enc_addr_in, 0, sizeof(enc_addr_in));
	enc_addr_in.sin6_family = AF_INET6;
	enc_addr_in.sin6_port = htons(4567);
	inet_pton(AF_INET6, "2001:0db8:85a3:08d3:1319:8a2e:0370:7344",
		  &enc_addr_in.sin6_addr);

	memset(&enc_addr, 0, sizeof(enc_addr));
	memcpy(&enc_addr, &enc_addr_in, sizeof(enc_addr_in));

	msg = gsm0808_enc_aoip_trasp_addr(&enc_addr);
	OSMO_ASSERT(msg);
	dec_addr = gsm0808_dec_aoip_trasp_addr(ctx, msg);

	OSMO_ASSERT(memcmp(&enc_addr, dec_addr, sizeof(enc_addr)) == 0);

	talloc_free(dec_addr);
	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec(const void *ctx)
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec *dec_sc;
	struct msgb *msg;

	memset(&enc_sc, 0, sizeof(enc_sc));
	enc_sc.fi = true;
	enc_sc.pt = true;
	enc_sc.type = 0x05;

	msg = gsm0808_enc_speech_codec(&enc_sc);
	OSMO_ASSERT(msg);
	dec_sc = gsm0808_dec_speech_codec(ctx, msg);

	OSMO_ASSERT(memcmp(&enc_sc, dec_sc, sizeof(enc_sc)) == 0);

	talloc_free(dec_sc);
	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec_ext_with_cfg(const void *ctx)
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec *dec_sc;
	struct msgb *msg;

	enc_sc.pi = true;
	enc_sc.tf = true;
	enc_sc.type = 0xab;
	enc_sc.type_extended = true;
	enc_sc.cfg_present = true;
	enc_sc.cfg = 0xcdef;

	msg = gsm0808_enc_speech_codec(&enc_sc);
	OSMO_ASSERT(msg);
	dec_sc = gsm0808_dec_speech_codec(ctx, msg);

	OSMO_ASSERT(memcmp(&enc_sc, dec_sc, sizeof(enc_sc)) == 0);

	talloc_free(dec_sc);
	msgb_free(msg);
}

static void test_gsm0808_enc_dec_speech_codec_ext(const void *ctx)
{
	struct gsm0808_speech_codec enc_sc;
	struct gsm0808_speech_codec *dec_sc;
	struct msgb *msg;

	enc_sc.fi = true;
	enc_sc.tf = true;
	enc_sc.type = 0xf2;
	enc_sc.type_extended = true;

	msg = gsm0808_enc_speech_codec(&enc_sc);
	OSMO_ASSERT(msg);
	dec_sc = gsm0808_dec_speech_codec(ctx, msg);

	OSMO_ASSERT(memcmp(&enc_sc, dec_sc, sizeof(enc_sc)) == 0);

	talloc_free(dec_sc);
	msgb_free(msg);
}

static bool speech_codec_cmp(struct gsm0808_speech_codec *a,
			     struct gsm0808_speech_codec *b)
{
	if (a->fi != b->fi)
		return false;
	if (a->pi != b->pi)
		return false;
	if (a->pt != b->pt)
		return false;
	if (a->tf != b->tf)
		return false;
	if (a->type != b->type)
		return false;
	if (a->cfg != b->cfg)
		return false;
	if (a->type_extended != b->type_extended)
		return false;
	if (a->cfg_present != b->cfg_present)
		return false;

	return true;
}

static void test_gsm0808_enc_dec_speech_codec_list(const void *ctx)
{
	struct gsm0808_speech_codec enc_sc1;
	struct gsm0808_speech_codec enc_sc2;
	struct gsm0808_speech_codec enc_sc3;
	struct msgb *msg;
	struct llist_head sc_list;
	struct llist_head *sc_list_decoded;
	struct gsm0808_speech_codec *sc;

	INIT_LLIST_HEAD(&sc_list);

	memset(&enc_sc1, 0, sizeof(enc_sc1));
	enc_sc1.pi = true;
	enc_sc1.tf = true;
	enc_sc1.type = 0xab;
	enc_sc1.type_extended = true;
	enc_sc1.cfg_present = true;
	enc_sc1.cfg = 0xcdef;

	memset(&enc_sc2, 0, sizeof(enc_sc2));
	enc_sc2.fi = true;
	enc_sc2.pt = true;
	enc_sc2.type = 0x05;

	memset(&enc_sc3, 0, sizeof(enc_sc3));
	enc_sc3.fi = true;
	enc_sc3.tf = true;
	enc_sc3.type = 0xf2;
	enc_sc3.type_extended = true;

	llist_add(&enc_sc3.list, &sc_list);
	llist_add(&enc_sc2.list, &sc_list);
	llist_add(&enc_sc1.list, &sc_list);

	msg = gsm0808_enc_speech_codec_list(&sc_list);
	sc_list_decoded = gsm0808_dec_speech_codec_list(ctx, msg);
	OSMO_ASSERT(msg->len == 0);

	llist_for_each_entry(sc, sc_list_decoded, list) {
		if(sc->type == 0xab) {
			OSMO_ASSERT(speech_codec_cmp(&enc_sc1,sc) == true);
		}
		else if(sc->type == 0x05) {
			OSMO_ASSERT(speech_codec_cmp(&enc_sc2,sc) == true);
		}
		else if(sc->type == 0xf2) {
			OSMO_ASSERT(speech_codec_cmp(&enc_sc3,sc) == true);
		}
		else {
			OSMO_ASSERT(false);
		}
	}

	talloc_free(sc_list_decoded);
	msgb_free(msg);
}

int main(int argc, char **argv)
{
	void *ctx;

	ctx = talloc_named_const(NULL, 0, "gsm0808_ctx");

	printf("Testing generation of GSM0808 messages\n");
	test_create_layer3();
	test_create_layer3_aoip(ctx);
	test_create_reset();
	test_create_clear_command();
	test_create_clear_complete();
	test_create_cipher_complete();
	test_create_cipher_reject();
	test_create_cm_u();
	test_create_sapi_reject();
	test_create_ass_compl();
	test_create_ass_compl_aoip(ctx);
	test_create_ass_fail();
	test_create_ass_fail_aoip(ctx);
	test_create_clear_rqst();
	test_create_dtap();
	test_prepend_dtap();
	test_enc_dec_aoip_trasp_addr_v4(ctx);
	test_enc_dec_aoip_trasp_addr_v6(ctx);
	test_gsm0808_enc_dec_speech_codec(ctx);
	test_gsm0808_enc_dec_speech_codec_ext(ctx);
	test_gsm0808_enc_dec_speech_codec_ext_with_cfg(ctx);
	test_gsm0808_enc_dec_speech_codec_list(ctx);

	printf("Done\n");

	talloc_report_full(ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(ctx) == 1);

	return EXIT_SUCCESS;
}
