/**
 * test.c: Check for expected output from generate_passphrase_sig() function
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * Copyright (C) 2012 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../../src/include/tse.h"

#define TSE_MAX_KEY_HEX_BYTES (TSE_MAX_KEY_BYTES * 2)

void usage(const char *name)
{
	fprintf(stderr, "%s PASSPHRASE SALT_HEX EXPECTED_SIG_HEX "
		"EXPECTED_FEKEK_HEX\n", name);
}

int main(int argc, char *argv[])
{
	char sig_hex[TSE_PASSWORD_SIG_SIZE + 1];
	char fekek[TSE_MAX_KEY_BYTES + 1];
	char fekek_hex[TSE_MAX_KEY_HEX_BYTES + 1];
	char salt[TSE_SALT_SIZE + 1];
	int rc;

	if (argc != 5 ||
	    strlen(argv[2]) != TSE_SALT_SIZE_HEX ||
	    strlen(argv[3]) != TSE_PASSWORD_SIG_SIZE ||
	    strlen(argv[4]) != TSE_MAX_KEY_HEX_BYTES) {
		usage(argv[0]);
		return EINVAL;
	}

	memset(sig_hex, 0, TSE_PASSWORD_SIG_SIZE + 1);
	memset(fekek, 0, TSE_MAX_KEY_BYTES + 1);
	memset(fekek_hex, 0, TSE_MAX_KEY_HEX_BYTES + 1);
	memset(salt, 0, TSE_SALT_SIZE + 1);
	from_hex(salt, argv[2], TSE_SALT_SIZE);

	rc = generate_passphrase_sig(sig_hex, fekek, salt, argv[1]);
	if (rc)
		return rc;

	to_hex(fekek_hex, fekek, TSE_MAX_KEY_BYTES);
	if (strcmp(sig_hex, argv[3]) ||
	    strcmp(fekek_hex, argv[4])) {
		return EINVAL;
	}

	return 0;
}

