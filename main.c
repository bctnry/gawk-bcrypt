#include <asm-generic/errno.h>
#include <errno.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "gawkapi.h"

#include "ow-crypt.h"

int plugin_is_GPL_compatible;

static const gawk_api_t *api;
static awk_ext_id_t ext_id;
static awk_bool_t (*init_func)(void) = NULL;
static const char *ext_version = NULL;

static awk_value_t*
do_crypt_gensalt(int nargs, awk_value_t* result, struct awk_ext_func* unused) {
	awk_value_t key, n;
	unsigned long count;
	assert(result != NULL);
	if (!get_argument(0, AWK_NUMBER, &n)) {
		count = 5;
	} else {
		count = ((unsigned long)(n.num_value));
	}
	char* buf = gawk_calloc(64, sizeof(char));
	FILE* fd = fopen("/dev/urandom", "rb");
	fread(buf, sizeof(char), 63, fd);
	fclose(fd);
	for (int i = 0; i < 64; i++) {
		buf[i] = (((unsigned char)buf[i])%64)+' '+1;
	}
	buf[63] = '\0';
	// NOTE: the return value of crypt_gensalt_ra is owned by owcrypt;
	// it's a static field.
	char* salt_setting = crypt_gensalt_ra("$2a$", count, buf, 64);
	gawk_free(buf);
	return  make_const_string(salt_setting, strlen(salt_setting), result);
}

static awk_value_t*
do_hash_with_salt(int nargs, awk_value_t* result, struct awk_ext_func* unused) {
	awk_value_t key, n;
	unsigned long count;
	assert(result != NULL);
	if (!get_argument(0, AWK_STRING, &key)) {
		fatal(ext_id, "bcrypt::hash_with_salt - not a string");
		return NULL;
	}
	if (!get_argument(1, AWK_NUMBER, &n)) {
		count = 5;
	} else {
		count = ((unsigned long)(n.num_value));
	}
	char* buf = gawk_calloc(64, sizeof(char));
	FILE* fd = fopen("/dev/urandom", "rb");
	fread(buf, sizeof(char), 63, fd);
	fclose(fd);
	for (int i = 0; i < 64; i++) {
		buf[i] = (((unsigned char)buf[i])%64)+' '+1;
	}
	buf[63] = '\0';
	char* salt_setting = crypt_gensalt("$2a$", count, buf, 64);
	gawk_free(buf);
	char* rr = crypt(key.str_value.str, salt_setting);
	return make_const_string(rr, strlen(rr), result);
}


static awk_value_t*
do_check_hash(int nargs, awk_value_t* result, struct awk_ext_func* unused) {
	awk_value_t key, hash;
	unsigned long count;
	assert(result != NULL);
	if (!get_argument(0, AWK_STRING, &key)) {
		fatal(ext_id, "bcrypt::check_hash - not a string");
		return NULL;
	}
	if (!get_argument(1, AWK_STRING, &hash)) {
		fatal(ext_id, "bcrypt::check_hash - not a string");
		return NULL;
	}
	char* ch = crypt(key.str_value.str, hash.str_value.str);
	return make_bool(strcmp(ch, hash.str_value.str) == 0, result);
}


static awk_ext_func_t func_table[] = {
	{"hash_with_salt", do_hash_with_salt, 2, 2, awk_false, NULL},
	{"check_hash", do_check_hash, 2, 2, awk_false, NULL},
};

dl_load_func(func_table, bcrypt, "bcrypt")

