/**
 * Author: Michael Halcrow
 *
 * Copyright (C) IBM
 *
 * Modified by Tyler Hicks <tyhicks@canonical.com> to fit into the Tse
 * test modern framework.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/include/tse.h"

int main(int argc, char *argv[])
{
	char passphrase[TSE_MAX_PASSWORD_LENGTH + 8];
	int passphrase_size;
	char decrypted_passphrase[TSE_MAX_PASSWORD_LENGTH + 1];
	int decrypted_passphrase_size;
	char salt[TSE_SALT_SIZE + 1];
	char *path;
	int i;
	int rc = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s path\n", argv[0]);
		exit(1);
	}
	path = argv[1];

	/* Sanity check */
	from_hex(salt, TSE_DEFAULT_SALT_HEX, TSE_SALT_SIZE);
	memcpy(passphrase, "012345679abcdef0\0", 17);
	passphrase_size = strlen(passphrase);
	if ((rc = tse_wrap_passphrase(path, "testwrappw", salt,
					   passphrase))) {
		fprintf(stderr, "tse_wrap_passphrase() returned "
			"rc = [%d]\n", rc);
		rc = 1;
		goto out;
	}
	if ((rc = tse_unwrap_passphrase(decrypted_passphrase, path,
					     "testwrappw", salt))) {
		fprintf(stderr, "tse_unwrap_passphrase() returned "
			"rc = [%d]\n", rc);
		rc = 1;
		goto out;
	}
	decrypted_passphrase_size = strlen(decrypted_passphrase);
	if (decrypted_passphrase_size != passphrase_size) {
		fprintf(stderr, "Invalid decrypted size [%d]; expected [%d]\n",
		       decrypted_passphrase_size, passphrase_size);
		rc = 1;
		goto out;
	}
	if (memcmp(decrypted_passphrase, passphrase, passphrase_size) != 0) {
		fprintf(stderr, "decrypted passphrase = [%s]; expected [%s]\n",
		       decrypted_passphrase, passphrase);
		rc = 1;
		goto out;
	}
	/* Comprehensive check */
	from_hex(salt, TSE_DEFAULT_SALT_HEX, TSE_SALT_SIZE);
	for (i = 0; i < TSE_MAX_PASSWORD_LENGTH; i++) {
		passphrase[i] = 'a' + i;
		passphrase[i + 1] = '\0';
		if ((rc = tse_wrap_passphrase(path, "testwrappw", salt,
						   passphrase))) {
			fprintf(stderr, "tse_wrap_passphrase() returned "
			       "rc = [%d]\n", rc);
			rc = 1;
			goto out;
		}
		if ((rc = tse_unwrap_passphrase(decrypted_passphrase,
						     path,
						     "testwrappw", salt))) {
			fprintf(stderr, "tse_unwrap_passphrase() returned "
				"rc = [%d]\n", rc);
			rc = 1;
			goto out;
		}
		decrypted_passphrase_size = strlen(decrypted_passphrase);
		if (decrypted_passphrase_size != (i + 1)) {
			fprintf(stderr, "Invalid decrypted size [%d]; expected "
				"[%d]\n", decrypted_passphrase_size, (i + 1));
			rc = 1;
			goto out;
		}
		if (memcmp(decrypted_passphrase, passphrase, (i + 1)) != 0) {
			fprintf(stderr, "decrypted passphrase = [%s]; expected "
				"[%s]\n", decrypted_passphrase, passphrase);
			rc = 1;
			goto out;
		}
	}
	/* Failure check */
	from_hex(salt, TSE_DEFAULT_SALT_HEX, TSE_SALT_SIZE);
	for (i = 0; i < 65; i++)
		passphrase[i] = 'a' + i;
	passphrase[66] = '\0';
	passphrase_size = strlen(passphrase);
	if ((rc = tse_wrap_passphrase(path, "testwrappw", salt,
					   passphrase)) == 0) {
		fprintf(stderr, "tse_wrap_passphrase() returned rc = 0; "
			"expected error result instead\n");
		rc = 1;
		goto out;
	}

	/* Ensure that an empty passphrase is rejected */
	if ((rc = tse_wrap_passphrase(path, "testwrappw", salt, "")) == 0) {
		fprintf(stderr, "tse_wrap_passphrase() wrapped an empty passphrase\n");
		rc = 1;
		goto out;
	}

	/* Ensure that an empty wrapping passphrase is rejected */
	if ((rc = tse_wrap_passphrase(path, "", salt, "testpassphrase")) == 0) {
		fprintf(stderr, "tse_wrap_passphrase() used an empty wrapping passphrase\n");
		rc = 1;
		goto out;
	}

	rc = 0;
out:
	return rc;
}
