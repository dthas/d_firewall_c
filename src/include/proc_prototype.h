//===========================================================================
// proc_prototype.h
//
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Originally by ZhaoFeng Liang <zhf.liang@hotmail.com>
//
//This file is part of DTHAS_FIREWALL.
//
//DTHAS_TLS is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; either version 2 of the License, or 
//(at your option) any later version.
//
//DTHAS_TLS is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with DTHAS_TLS; If not, see <http://www.gnu.org/licenses/>.  
//===========================================================================

#ifndef	_PROC_PROTOTYPE_H_
#define	_PROC_PROTOTYPE_H_

//main.c
PUBLIC	s32	main(s32 argc, s8*argv[]);

//keycap.c
PUBLIC	void	key_cap(s8 *str);
PUBLIC	s8	key_send(s8 *str);

//smtp.c
PUBLIC	void	tls_init();
PUBLIC	void 	smtp_main(s16 nPort, s8 *mail_data);
PUBLIC	void 	https_main(s16 nPort, s8 *mail_data);

//string.c
PUBLIC 	void 	strcpy_1(char *dest, char *src, s32 len);
PUBLIC 	s8 	strcmp_1(char *dest, char *src);

//sha512.c
PUBLIC	u8*	sha512_init(s8* plain_text, s32 len);

//sha256.c
PUBLIC	u8*	sha256_init(s8* plain_text, s32 len);

//tls.c
PUBLIC	u8* PRF_handler_256(u8* secret, u8* label_1, u8* seed, u8* res, s32 output_len_byte, s32 secret_len, s32 seed_len);
PUBLIC	u8* HMAC_SHA256(u8* key, u8* mes , s32 key_len ,s32 mes_len);

//tls_128_256.c
PUBLIC	s32 ghash_128(u8* key, s32 key_len, u8* x, s32 x_len, u8* res, s32 res_len);
PUBLIC	s32 ghash_128_1(u8* h, s32 h_len, u8* aad, s32 aad_len, u8* ctext, s32 c_len, u8* res, s32 res_len);
PUBLIC	u8* gctr(u8 *icb, u8* key, u8* ptext, u8* ctext, s32 icb_len, s32 key_len, s32 ptext_len, s32 ctext_len);
PUBLIC	s32 aead_encrypted_128(u8* key, u8 *key_rev, s32 key_len, u8* iv, u8* iv_rev, s32 iv_len, u8* plaintext, s32 plaintext_len, u8* addtional_data, s32 addtional_data_len, u8* C, s32 c_len, u8* T, s32 t_len);

//md5.c
PUBLIC	u8*	md5_init(s8* plain_text, s32 len);

//rsa.c
PUBLIC	void	rsa_init();
PUBLIC	void	rsa_handler(s8* text, s32 text_len);
PUBLIC	u8*	rsa_en_public(s8* plain_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf);
PUBLIC	u8*	rsa_en_public_main(s8 *c_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf, s32 text_len);
PUBLIC	u8*	rsa_de_private(s8* plain_text, s8 *Private_key_buf, s8* Private_key_exponent_buf);
PUBLIC	u8*	rsa_de_private_main(s8 *c_text,s8 *Private_key_buf, s8* Private_key_exponent_buf, s8* Prime1_buf, s8* Prime2_buf, s8* exponent1_buf, s8* exponent2_buf, s8* coefficient_buf, s32 text_len);
PUBLIC	u8*	rsa_en_private_main(s8 *plain_text, s8 *Private_key_buf, s8* Private_key_exponent_buf, s8* Prime1_buf, s8* Prime2_buf, s8* exponent1_buf, s8* exponent2_buf, s8* coefficient_buf, s32 text_len);
PUBLIC	u8*	rsa_de_public_main(s8 *c_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf, s32 text_len);
PUBLIC	u8*	rsa_en_private(s8* c_text, s8 *Private_key_buf, s8* Private_key_exponent_buf);
PUBLIC	u8*	rsa_de_public(s8* plain_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf);
PUBLIC	u8*	get_prikey();
PUBLIC	u8*	get_pubkey();
PUBLIC	u8*	get_prikey_exponent();
PUBLIC	u8*	get_pubkey_exponent();

//dh.c
PUBLIC	u8*	dh_get_pubkey_main(s8 *aphar, s8 *n_buf, s8 *exponent_buf, s32 text_len);
PUBLIC	u8*	dh_gen_pubkey(s8* aphar, s8 *n_buf, s8 *exponent_buf);

//10001系列只是为了减少运算时间而设立的，只针对公钥指数是0x10001
PUBLIC	u8*	rsa_en_public_10001(s8* plain_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf);
PUBLIC	u8*	rsa_en_public_main_10001(s8 *c_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf, s32 text_len);
PUBLIC	u8*	rsa_de_public_main_10001(s8 *c_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf, s32 text_len);
PUBLIC	u8*	rsa_de_public_10001(s8* plain_text, s8 *Public_key_buf, s8 *Public_key_exponent_buf);

//aes256.c
PUBLIC	void	aes256_cbc_encrypt(u8 *plain_text, struct cipherkey* ck, struct plaintext *res, u8* res_final, s32 len);
PUBLIC	void	aes256_cbc_decrypt(u8 *plain_text, struct cipherkey* ck, struct plaintext *res, u8* res_final, s32 len);
PUBLIC	void	aes256_encrypt(struct plaintext *pt, struct cipherkey* ck, struct plaintext *res);
PUBLIC	void	aes256_decrypt(struct plaintext *pt, struct cipherkey* ck, struct plaintext *res);

//aes128.c
PUBLIC	void	aes128_cbc_encrypt(u8 *plain_text, struct cipherkey128* ck, struct plaintext *res, u8* res_final, s32 len);
PUBLIC	void	aes128_cbc_decrypt(u8 *plain_text, struct cipherkey128* ck, struct plaintext *res, u8* res_final, s32 len);
PUBLIC	void	aes128_encrypt(struct plaintext *pt, struct cipherkey128* ck, struct plaintext *res);
PUBLIC	void	aes128_decrypt(struct plaintext *pt, struct cipherkey128* ck, struct plaintext *res);


//ecc256.c
PUBLIC	u8*	ecc_genkey(s8* na, s8 *gx, s8* gy, s8* a, s8* b, s8 *n, s32 na_len, s32 g_len, s32 a_len, s32 b_len, s32 n_len);
PUBLIC	u8*	ecc_genkey_main(s8* na, s8 *gx, s8* gy, s8* a, s8* b, s8 *pn, s32 na_len, s32 g_len, s32 a_len, s32 b_len, s32 n_len);
PUBLIC	u8*	ecc_genkey_main_10001(s8* na, s8 *gx, s8* gy, s8* a, s8* b, s8 *pn, s32 na_len, s32 g_len, s32 a_len, s32 b_len, s32 n_len);

//lib_crytopgraph.c
PUBLIC 	u64 	Majority(u64 x, u64 y, u64 z);
PUBLIC 	u64 	Conditional(u64 x, u64 y, u64 z);
PUBLIC 	u64 	RotR(u64 x, s8 i);
PUBLIC 	u32 	RotL32(u32 x, s8 i);
PUBLIC 	u64 	ShL(u64 x, s8 i);
PUBLIC 	u64 	ShR(u64 x, s8 i);
PUBLIC 	u64 	Rotate(u64 x, s8 l, s8 m, s8 n);
PUBLIC 	u64 	RotShift(u64 x, s8 l, s8 m, s8 n);
PUBLIC 	u32 	F(u32 x, u32 y, u32 z);
PUBLIC 	u32 	G(u32 x, u32 y, u32 z);
PUBLIC 	u32 	H(u32 x, u32 y, u32 z);
PUBLIC 	u32 	I(u32 x, u32 y, u32 z);
PUBLIC 	void 	FF(u32 *a, u32 b, u32 c, u32 d, u32 mj, s8 s, u32 ti);
PUBLIC 	void 	GG(u32 *a, u32 b, u32 c, u32 d, u32 mj, s8 s, u32 ti);
PUBLIC 	void 	HH(u32 *a, u32 b, u32 c, u32 d, u32 mj, s8 s, u32 ti);
PUBLIC 	void 	II(u32 *a, u32 b, u32 c, u32 d, u32 mj, s8 s, u32 ti);
PUBLIC 	u64 	pr_block(u8 *blk, s32 size_bits);
PUBLIC 	u64 	pr_buf(u8 *buf, s32 size_bits);
PUBLIC 	u64 	pr_buf_1(u8 *buf, s32 size_bits);
PUBLIC 	u64 	pr_buf_2(u8 *buf, s32 size_bits);
PUBLIC 	u64 	pr_buf_3(u8 *buf, s32 size_bits, s32 row_bits);
PUBLIC 	u64 	pr_buf_4(u8 *buf, s32 size_bits, s32 row_bits);
PUBLIC 	u64 	pr_buf5(u8 *buf, s32 size_bits);
PUBLIC 	u64 	pr_block_1(u8 *blk, s32 size_bits);
PUBLIC 	u32 	pr_block_2(u8 *blk, s32 size_bits);
PUBLIC 	u32 	pr_block_3(u8 *blk, s32 size_bits);
PUBLIC 	u64 	pr_block_4(u8 *blk, s32 size_bits);
PUBLIC 	u64 	pr_block5(u8 *blk, s32 size_bits);
PUBLIC	void	outfile(s8 *filename, s8 *data, s32 len);

//lib.c
PUBLIC 	u16 	little_big_16(u16 val);
PUBLIC 	void 	little_big_32(u32 * val);
PUBLIC 	void 	little_big_64(u64 * val);
PUBLIC 	void 	little_big_128(u64 * low_byte_val);
PUBLIC 	void 	memset_u64(u64* buf, u64 ch, s32 size);
PUBLIC 	u8 	s2i(u8 ch);
PUBLIC	u64 	pow(u64 a, u64 b);

//base64.c
PUBLIC	void 	base64_en(u8 *src, u8 *dst);
PUBLIC	void 	base64_de(u8 *src, u8 *dst);

//bin2pem.c
PUBLIC	void 	bin2pem(u8 *src, u8 *dst, s32 src_len);

//lib_bignum_32bit.c
PUBLIC	void	inv_buf_by_byte(u8 *dst, u8 *src, s32 len);
PUBLIC	s8	bignum_Cmp_H2L(u8 *a, u8 *b, s32 len);
PUBLIC	s8	bignum_Cmp_L2H(u8 *a, u8 *b, s32 len);
PUBLIC	void	bignum_SHL_BITS(u8 *data, s32 len, s32 num_bits);
PUBLIC	void	bignum_SHR_BITS(u8 *data, s32 len, s32 num_bits);
PUBLIC	void	bignum_SHL_BYTE(u8 *data, s32 len);
PUBLIC	void	bignum_SHR_BYTE(u8 *data, s32 len);
PUBLIC	void	bignum_SHL_BYTES(u8 *data, s32 len, s32 num_bytes);
PUBLIC	void	bignum_SHR_BYTES(u8 *data, s32 len, s32 num_bytes);
PUBLIC	void	bignum_Mov(u8 *dst, u8 *src, s32 len);
PUBLIC	void	bignum_Add_L2H(u8 *dst, u8 *src, s32 len);
PUBLIC	void	bignum_Add_H2L(u8 *dst, u8 *src, s32 len);
PUBLIC	s8	bignum_Sub_L2H(u8 *remain, u8 *dst, u8 *src, s32 len);
PUBLIC	void	bignum_Sub_H2L(u8 *remain, u8 *dst, u8 *src, s32 len);
PUBLIC	void	bignum_Mul_L2H(u8 *a, u8 *b, s32 len_a, s32 len_b);
PUBLIC	void	bignum_Mul_H2L(u8 *a, u8 *b, s32 len_a, s32 len_b);
PUBLIC	void	bignum_Mod(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res);
PUBLIC	s8	bignum_get_mulsign(s8 a, s8 b);
PUBLIC	s8	bignum_ExtendedEuclid(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res, s8 sbit_a, s8 sbit_b);
PUBLIC	s8	bignum_AntiUnit_s(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res, s8 sbit_a, s8 sbit_b);
PUBLIC	s8	bignum_Sub_H2L_s(u8 *remain, u8 *dst, u8 *src, s32 len, s8 sbit_a, s8 sbit_b);
PUBLIC	void	bignum_Mod256_s(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res, s8 sbit_a);
PUBLIC	void	bignum_Div256(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res);
PUBLIC	void	bignum_Mod256(u8 *res, u8 *a, u8 *b, s32 len_a, s32 len_b, s32 len_res);
PUBLIC	s8	bignum_Add_H2L_s(u8 *dst, u8 *src, s32 len, s8 sbit_dst, s8 sbit_src);

#endif
