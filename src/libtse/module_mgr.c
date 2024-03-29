/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 * 	      Trevor Highland <trevor.highland@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "../include/tse.h"
#include "../include/decision_graph.h"

static struct param_node key_module_select_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"key"},
	.prompt = "Select key type to use for newly created files",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = DISPLAY_TRANSITION_NODE_VALS | TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 0,
	.tl = {{0}}
};

/**
 * sig_param_node_callback
 *
 * The Tse utilities may modify the decision graph
 * in-flight. This is one example of that happening.
 *
 * By default, root_param_node will pull a "sig=" option out of the
 * already-supplied name/value pair list and skip the key module
 * selection stage altogether. If there is no "sig=" option provided
 * in the list (condition: node->val == NULL), then change the
 * next_token transition node pointer to point to the key module
 * selection node.
 */
static int
sig_param_node_callback(struct tse_ctx *ctx, struct param_node *node,
			struct val_node **head, void **foo)
{
	char *param;
	int rc = 0;

	if (!node->val) {
		node->tl[0].next_token = &key_module_select_node;
		goto out;
	}
	if (strcmp(node->val, "NULL") == 0) {
		node->tl[0].next_token = &key_module_select_node;
		goto out;
	}
	rc = asprintf(&param, "tse_sig=%s", node->val);
	if (rc == -1) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	rc = stack_push(head, param);
out:
	return rc;
}

static struct param_node tse_cipher_param_node;

static struct param_node root_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"sig"},
	.prompt = "Existing key signature",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = "NULL",
	.flags = TSE_PARAM_FLAG_NO_VALUE | TSE_NO_AUTO_TRANSITION,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &tse_cipher_param_node,
		.trans_func = sig_param_node_callback}}
};

/* returns: 
 * 	on_null for str == NULL
 *	1 for str=="yes" or "y"
 *	0 for str=="no" or "n"
 *	-1 elsewhere */
static int is_yes(const char *str, int on_null)
{
	if (str) {
		if (!strcmp(str,"y") || !strcmp(str,"yes"))
			return 1;
		if (!strcmp(str,"no") || !strcmp(str,"n"))
			return 0;
	} else
		return on_null;

	return -1;
}


/* returns: 0 for success
 *	    WRONG_VALUE if node->val is none of  'yes','y','no','n'
 *	    <0 for error
 */
static int stack_push_if_yes(struct param_node *node, struct val_node **head,
			     char *opt_name)
{
	int rc;

	if (((rc=is_yes(node->val, 0)) == 1) || (node->flags & PARAMETER_SET)) {
		rc = stack_push(head, opt_name);
	} else if (rc == -1)
		rc = WRONG_VALUE;
	free(node->val);
	node->val = NULL;
	return rc;
}

static int get_hmac(struct tse_ctx *ctx, struct param_node *node,
		    struct val_node **head, void **foo)
{
	return stack_push_if_yes(node, head, "tse_hmac");
}

static int get_passthrough(struct tse_ctx *ctx, struct param_node *node,
			   struct val_node **head, void **foo)
{
	return stack_push_if_yes(node, head, "tse_passthrough");
}

static int get_xattr(struct tse_ctx *ctx, struct param_node *node,
			   struct val_node **head, void **foo)
{
	return stack_push_if_yes(node, head, "tse_xattr_metadata");
}

static int get_encrypted_passthrough(struct tse_ctx *ctx,
				     struct param_node *node,
				     struct val_node **head, void **foo)
{
	return stack_push_if_yes(node, head, "tse_encrypted_view");
}

static struct param_node end_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"end"},
	.prompt = "end",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_NO_VALUE,
	.num_transitions = 0,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = NULL,
		.trans_func = NULL}}
};

static struct param_node enable_filename_crypto_param_node;

static int filename_crypto_fnek_sig_callback(struct tse_ctx *ctx,
					     struct param_node *node,
					     struct val_node **head, void **foo)
{
	char *param;
	int rc = 0;

	if (!node->val) {
		node->flags = TSE_PARAM_FLAG_ECHO_INPUT;
		enable_filename_crypto_param_node.tl[0].next_token =
			node->tl[0].next_token;
		node->tl[0].next_token = &enable_filename_crypto_param_node;
		goto out;
	}
	if (strcmp(node->val, "NULL") == 0) {
		node->flags = TSE_PARAM_FLAG_ECHO_INPUT;
		enable_filename_crypto_param_node.tl[0].next_token =
			node->tl[0].next_token;
		node->tl[0].next_token = &enable_filename_crypto_param_node;
		goto out;
	}
	rc = asprintf(&param, "tse_fnek_sig=%s", node->val);
	if (rc == -1) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	rc = stack_push(head, param);
out:
	return rc;
}

static struct param_node filename_crypto_fnek_sig_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_fnek_sig"},
	.prompt = "Filename Encryption Key (FNEK) Signature",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.suggested_val = NULL,
	.flags = TSE_PARAM_FLAG_NO_VALUE | TSE_NO_AUTO_TRANSITION,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &end_param_node,
		.trans_func = filename_crypto_fnek_sig_callback}}
};

static int get_enable_filename_crypto(struct tse_ctx *ctx,
					struct param_node *node,
					struct val_node **head, void **foo)
{
	int yn, rc = 0;

	if (((yn=is_yes(node->val, 0)) > 0)
	    || (node->flags & PARAMETER_SET)) {
		int i;
		struct val_node *val_node;

		for (i = 0;
		     i < filename_crypto_fnek_sig_param_node.num_transitions;
		     i++)
			filename_crypto_fnek_sig_param_node.tl[i].next_token =
				node->tl[0].next_token;
		node->tl[0].next_token = &filename_crypto_fnek_sig_param_node;
		val_node = (*head);
		while (val_node) {
			if (strncmp(val_node->val, "tse_sig=", 13) == 0) {
				rc  = asprintf(&filename_crypto_fnek_sig_param_node.suggested_val,
					       "%s",
					       &((char *)val_node->val)[13]);
				if (rc == -1) {
					rc = -ENOMEM;
					syslog(LOG_ERR,
					       "%s: No memory whilst "
					       "attempting to write [%s]\n",
					       __FUNCTION__,
					       &((char *)val_node->val)[13]);
					goto out_free;
				}
				rc = 0;
				break;
			}
			val_node = val_node->next;
		}
	} else if (node->val) {
		if (yn < 0)
			rc = WRONG_VALUE;
	} else {
		/* default: no */;
	}
out_free:
	if (node->val) {
		free(node->val);
		node->val = NULL;
	}
	return rc;
}

static struct param_node enable_filename_crypto_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_enable_filename_crypto"},
	.prompt = "Enable filename encryption (y/n)",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &filename_crypto_fnek_sig_param_node,
		.trans_func = get_enable_filename_crypto}}
};

static struct param_node tse_version_support_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"end"},
	.prompt = "end",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_NO_VALUE,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = NULL,
		.trans_func = NULL}}
};

static struct param_node encrypted_passthrough_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_encrypted_view"},
	.prompt = "Pass through encrypted versions of all files (y/N)",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = "n",
	.flags = TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &end_param_node,
		.trans_func = get_encrypted_passthrough}}
};

static struct param_node xattr_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_xattr"},
	.prompt = "Write metadata to extended attribute region (y/N)",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = "n",
	.flags = TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &end_param_node,
		.trans_func = get_xattr}}
};

static struct param_node passthrough_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_passthrough"},
	.prompt = "Enable plaintext passthrough (y/n)",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &end_param_node,
		.trans_func = get_passthrough}}
};

static struct param_node hmac_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_hmac"},
	.prompt = "Enable HMAC integrity verification (y/N)",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_ECHO_INPUT,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &end_param_node,
		.trans_func = get_hmac}}
};

static struct param_node tse_key_bytes_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_key_bytes"},
	.prompt = "Select key bytes",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = (DISPLAY_TRANSITION_NODE_VALS
		  | TSE_PARAM_FORCE_DISPLAY_NODES
		  | TSE_PARAM_FLAG_ECHO_INPUT),
	.num_transitions = 0,
	.tl = {{0}}
};

static struct supported_key_bytes {
	char *cipher_name;
	uint32_t key_bytes;
} supported_key_bytes[] = {
	{"aes", 16},
	{"aes", 32},
	{"aes", 24},
	{"anubis", 16},
	{"anubis", 32},
	{"des3_ede", 24},
	{"serpent", 16},
	{"serpent", 32},
	{"tnepres", 16},
	{"tnepres", 32},
	{"tea", 16},
	{"xeta", 16},
	{"xtea", 16},
	{"cast5", 16},
	{"cast6", 16},
	{"cast6", 32},
	{"twofish", 16},
	{"twofish", 32},
	{"blowfish", 16},
	{"blowfish", 32},
	{"blowfish", 56},
	{"khazad", 16},
	{"arc4", 16},
	{"arc4", 32},
	{"sm4",16},
	{NULL, 0}
};

static int tf_tse_key_bytes(struct tse_ctx *ctx,
				 struct param_node *node,
				 struct val_node **head, void **foo)
{
	char *opt;
	int rc = 0;

	rc = asprintf(&opt, "tse_key_bytes=%s", node->val);
	free(node->val);
	node->val = NULL;
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = stack_push(head, opt);
out:
	return rc;
}

static int init_tse_key_bytes_param_node(char *cipher_name, 
					      uint32_t min, uint32_t max)
{
	int i;
	int rc = 0;

	i = 0;
	while (supported_key_bytes[i].cipher_name) {
		if ((supported_key_bytes[i].key_bytes >= min) && 
		    (supported_key_bytes[i].key_bytes <= max) &&
		    (strcmp(cipher_name, supported_key_bytes[i].cipher_name)
		      == 0)) {
			struct transition_node *tn;
			
			tn = &tse_key_bytes_param_node.tl[
				tse_key_bytes_param_node.num_transitions];
			rc = asprintf(&tn->val, "%"PRIu32,
				      supported_key_bytes[i].key_bytes);
			if (rc == -1) {
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
			if (!tse_key_bytes_param_node.suggested_val) {
				rc = asprintf(&tse_key_bytes_param_node.suggested_val,
					      "%"PRIu32,
					      supported_key_bytes[i].key_bytes);
				if (rc == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
			}
			tn->next_token = &tse_version_support_node;
			tn->trans_func = tf_tse_key_bytes;
			tse_key_bytes_param_node.num_transitions++;
		}
		i++;
	}
	if (tse_key_bytes_param_node.num_transitions == 0) {
		syslog(LOG_ERR, "Error initializing key_bytes selection: "
		       "there is no posibility left for used params\n");
		return -EINVAL;
	}
out:
	return rc;
}

static int parse_key_bytes(uint32_t *bytes, const char *str)
{
	uintmax_t tmp;
	char *eptr;

	if (str[0] == '-')
		return -ERANGE;

	errno = 0;
	tmp = strtoumax(str, &eptr, 10);
	if (eptr == str)
		return -EINVAL;
	else if (tmp == UINTMAX_MAX && errno == ERANGE)
		return -ERANGE;
	else if (tmp > UINT32_MAX)
		return -ERANGE;

	*bytes = (uint32_t)tmp;
	return 0;
}

static int tf_tse_cipher(struct tse_ctx *ctx, struct param_node *node,
			      struct val_node **head, void **foo)
{
	char *opt;
	int rc;
	uint32_t min = 0, max = 999999;
	struct val_node *tmp = *head, *tmpprev = NULL;

	while (tmp) {
		char *ptr;
		int popval = 0;
		if (tmp->val && (strstr(tmp->val,"max_key_bytes=") != NULL) && 
		    ((ptr=strchr(tmp->val,'=')) != NULL)) {
			rc = parse_key_bytes(&max, ++ptr);
			if (rc)
				return rc;
			popval = 1;
		}
		if (tmp->val && (strstr(tmp->val,"min_key_bytes=") != NULL) && 
		    ((ptr=strchr(tmp->val,'=')) != NULL)) {
			rc = parse_key_bytes(&min, ++ptr);
			if (rc)
				return rc;
			popval = 1;
		}
		if (popval) {
			if (tmp == *head)
				*head = (*head)->next;
			stack_pop(&tmp);
			if (tmpprev != NULL)
				tmpprev->next = tmp;
		}
		tmpprev = tmp;
		tmp = tmp->next;
	}

	rc = init_tse_key_bytes_param_node(node->val, min, max);
	if (rc) {
		syslog(LOG_ERR, "%s: Error initializing key_bytes param node; "
		       "rc = [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	rc = asprintf(&opt, "tse_cipher=%s", node->val);
	free(node->val);
	node->val = NULL;
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	if (tse_verbosity)
		syslog(LOG_INFO, "%s: Pushing onto stack; opt = [%s]\n",
		       __FUNCTION__, opt);
	rc = stack_push(head, opt);
out:
	return rc;
}

static struct param_node tse_cipher_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"tse_cipher"},
	.prompt = "Select cipher",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = (DISPLAY_TRANSITION_NODE_VALS | TSE_DISPLAY_PRETTY_VALS
		  | TSE_PARAM_FLAG_ECHO_INPUT),
	.num_transitions = 0,
	.tl = {{0}}
};

static struct cipher_descriptor {
	char *name;
	uint32_t blocksize;
	uint32_t min_keysize;
	uint32_t max_keysize;
} cipher_descriptors[] = {
	{"aes", 16, 16, 32},
	{"blowfish", 8, 16, 56},
	{"des3_ede", 8, 24, 24},
	{"twofish", 16, 16, 32},
	{"cast6", 16, 16, 32},
	{"cast5", 8, 5, 16},
	{"sm4", 16, 16},
	{NULL, 0, 0, 0}
};

static int init_tse_cipher_param_node()
{
	struct cipher_descriptor *cd = cipher_descriptors;
	int rc = 0;

	while (cd && cd->name) {
		struct transition_node *tn;

		if (tse_cipher_param_node.num_transitions
		    >= MAX_NUM_TRANSITIONS) {
			syslog(LOG_WARNING, "%s: Exceeded maximum number of "
			       "transition nodes [%d] whilst constructing "
			       "cipher list\n", __FUNCTION__,
			       MAX_NUM_TRANSITIONS);
			goto out;
		}
		tn = &tse_cipher_param_node.tl[
			tse_cipher_param_node.num_transitions];
		rc = asprintf(&tn->val, "%s", cd->name);
		if (rc == -1) {
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
		if (!tse_cipher_param_node.suggested_val) {
			rc = asprintf(&tse_cipher_param_node.suggested_val,
				      "%s", cd->name);
			if (rc == -1) {
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
		}
		rc = asprintf(&tn->pretty_val, "%s: blocksize = %d; "
			      "min keysize = %d; max keysize = %d", cd->name,
			      cd->blocksize, cd->min_keysize, cd->max_keysize);
		if (rc == -1) {
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
		tn->next_token = &tse_key_bytes_param_node;
		tn->trans_func = tf_tse_cipher;
		tse_cipher_param_node.num_transitions++;
		cd++;
	}
out:
	return rc;
}

static int
another_key_param_node_callback(struct tse_ctx *ctx,
				struct param_node *node,
				struct val_node **head, void **foo)
{
	struct tse_name_val_pair *nvp = ctx->nvp_head->next;
	int rc = 0;

	while (nvp) {
		int i;

		if (nvp->flags & TSE_PROCESSED) {
			nvp = nvp->next;
			continue;
		}
		if (tse_verbosity)
			syslog(LOG_INFO, "Comparing nvp->name = [%s] to "
			       "key_module_select_node.mnt_opt_names[0] = "
			       "[%s]\n", nvp->name,
			       key_module_select_node.mnt_opt_names[0]);
		if (strcmp(nvp->name,
			   key_module_select_node.mnt_opt_names[0]) != 0) {
			nvp = nvp->next;
			continue;
		}
		for (i = 0; i < key_module_select_node.num_transitions; i++)
			if (strcmp(nvp->value,
				   key_module_select_node.tl[i].val) == 0) {
				node->tl[0].next_token =
					&key_module_select_node;
				if (tse_verbosity)
					syslog(LOG_INFO,
					       "Found another nvp match\n");
				goto out;
			}
		nvp = nvp->next;
	}
	node->tl[0].next_token = &tse_cipher_param_node;
out:
	return rc;
}

/**
 * Check for the existence of another transition node match in the
 * name/value pair list.
 */
static struct param_node another_key_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"another_key"},
	.prompt = "Internal check for another key",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = "NULL",
	.flags = TSE_PARAM_FLAG_NO_VALUE | TSE_NO_AUTO_TRANSITION,
	.num_transitions = 1,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = &tse_cipher_param_node,
		.trans_func = another_key_param_node_callback}}
};

static int
fill_in_decision_graph_based_on_version_support(struct param_node *root,
						uint32_t version)
{
	struct param_node *last_param_node = &tse_version_support_node;
	int rc;

	tse_set_exit_param_on_graph(root, &another_key_param_node);
	rc = init_tse_cipher_param_node();
	if (rc) {
		syslog(LOG_ERR,
		       "%s: Error initializing cipher list; rc = [%d]\n",
		       __FUNCTION__, rc);
		goto out;
	}
	if (tse_supports_plaintext_passthrough(version)) {
		int i;

		for (i = 0; i < last_param_node->num_transitions; i++)
			last_param_node->tl[i].next_token =
				&passthrough_param_node;
		rc = asprintf(&passthrough_param_node.suggested_val, "n");
		if (rc == -1) {
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
		last_param_node = &passthrough_param_node;
	}
	if (tse_supports_hmac(version)) {
		int i;

		for (i = 0; i < last_param_node->num_transitions; i++)
			last_param_node->tl[i].next_token =
				&hmac_param_node;
		last_param_node = &hmac_param_node;
	}
	if (tse_supports_xattr(version)) {
		int i;

		for (i = 0; i < last_param_node->num_transitions; i++)
			last_param_node->tl[i].next_token = &xattr_param_node;
		last_param_node = &xattr_param_node;
		for (i = 0; i < last_param_node->num_transitions; i++)
			last_param_node->tl[i].next_token =
				&encrypted_passthrough_param_node;
		last_param_node = &encrypted_passthrough_param_node;
	}
	if (tse_supports_filename_encryption(version)) {
		int i;

		rc = asprintf(&enable_filename_crypto_param_node.suggested_val,
			      "n");
		if (rc == -1) {
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
		for (i = 0; i < last_param_node->num_transitions; i++)
			last_param_node->tl[i].next_token =
				&filename_crypto_fnek_sig_param_node;
		last_param_node = &filename_crypto_fnek_sig_param_node;
	}
out:
	return rc;
}

static struct param_node dummy_param_node = {
	.num_mnt_opt_names = 1,
	.mnt_opt_names = {"dummy"},
	.prompt = "dummy",
	.val_type = VAL_STR,
	.val = NULL,
	.display_opts = NULL,
	.default_val = NULL,
	.flags = TSE_PARAM_FLAG_NO_VALUE,
	.num_transitions = 0,
	.tl = {{.val = "default",
		.pretty_val = "default",
		.next_token = NULL,
		.trans_func = NULL}}
};

/**
 * tse_process_decision_graph
 * @key_module_only: Only process the key module; set this if you are,
 *                   for instance, only inserting the key into the
 *                   user session keyring
 *
 * Called from: utils/mount.tse.c::main()
 *
 * Some values may be duplicated. For instance, if the user specifies
 * two keys of the same type, then we want to process both keys:
 *
 * key=passphrase:passwd=pass1,key=passphrase:passwd=pass1
 *
 * 
 */
int tse_process_decision_graph(struct tse_ctx *ctx,
				    struct val_node **mnt_params,
				    uint32_t version, char *opts_str,
				    int key_module_only)
{
	struct tse_name_val_pair nvp_head;
	struct tse_name_val_pair rc_file_nvp_head;
	struct tse_key_mod *key_mod;
	struct tse_name_val_pair allowed_duplicates;
	struct tse_name_val_pair *ad_cursor;
	int rc;

	ad_cursor = &allowed_duplicates;
	ad_cursor->next = NULL;
	/* Start with the key module type. Generate the options from
	 * the detected modules that are available */
	rc = tse_register_key_modules(ctx);
	if (rc) {
		syslog(LOG_ERR, "Error attempting to get key module list; "
		       "rc = [%d]\n", rc);
		goto out;
	}
	if ((ad_cursor->next = malloc(sizeof(allowed_duplicates))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	ad_cursor = ad_cursor->next;
	ad_cursor->next = NULL;
	if ((rc = asprintf(&ad_cursor->name, "%s",
			   key_module_select_node.mnt_opt_names[0])) == -1) {
		rc = -ENOMEM;
		goto out_free_allowed_duplicates;
	}
	key_module_select_node.num_transitions = 0;
	key_mod = ctx->key_mod_list_head.next;
	while (key_mod) {
		struct transition_node *trans_node;

		if ((rc =
		     key_mod->ops->get_param_subgraph_trans_node(&trans_node,
								 version))) {
			syslog(LOG_INFO, "Key module [%s] does not have a "
			       "subgraph transition node; attempting to build "
			       "a linear subgraph from its parameter list\n",
			       key_mod->alias);
			if ((rc = tse_build_linear_subgraph(&trans_node,
								 key_mod))) {
				syslog(LOG_WARNING, "Error attempting to build "
				       "linear subgraph for key module [%s]; "
				       "excluding; rc = [%d]\n",
				       key_mod->alias, rc);
				key_mod = key_mod->next;
				continue;
			}
		}
		if (trans_node == NULL) {
			if ((rc = tse_build_linear_subgraph(&trans_node,
								 key_mod))) {
				syslog(LOG_WARNING, "Error attempting to build "
				       "linear subgraph for key module [%s]; "
				       "excluding; rc = [%d]\n",
				       key_mod->alias, rc);
				key_mod = key_mod->next;
				continue;
			}
		}
		if ((rc =
		     add_transition_node_to_param_node(&key_module_select_node,
						       trans_node))) {
			syslog(LOG_ERR, "Error attempting to add transition "
			       "node to param node; rc = [%d]\n", rc);
			goto out_free_allowed_duplicates;
		}
		/* Key module parameters may be duplicated, since
		 * the user may specify multiple keys. Make sure that
		 * the allowed_duplicates list has the parameters for
		 * this key module. */
		if ((rc = tse_insert_params_in_subgraph(ad_cursor,
							     trans_node))) {
			syslog(LOG_ERR, "Error attempting to insert allowed "
			       "duplicate parameters into subgraph for key "
			       "module; rc = [%d]\n", rc);
			goto out_free_allowed_duplicates;
		}
		key_mod = key_mod->next;
	}
	if (key_module_only == TSE_ASK_FOR_ALL_MOUNT_OPTIONS) {
		rc = fill_in_decision_graph_based_on_version_support(
			&key_module_select_node, version);
		if (rc) {
			syslog(LOG_ERR, "%s: Error attempting to fill in "
			       "decision graph; rc = [%d]\n", __FUNCTION__, rc);
			goto out;
		}
	} else
		tse_set_exit_param_on_graph(&key_module_select_node,
						 &dummy_param_node);
	memset(&nvp_head, 0, sizeof(struct tse_name_val_pair));
	memset(&rc_file_nvp_head, 0, sizeof(struct tse_name_val_pair));
	tse_parse_rc_file(&rc_file_nvp_head);
	rc = tse_parse_options(opts_str, &nvp_head);
	tse_nvp_list_union(&rc_file_nvp_head, &nvp_head,
				&allowed_duplicates);
	if (tse_verbosity) {
		struct tse_name_val_pair *nvp_item = rc_file_nvp_head.next;

		while (nvp_item) {
			if (tse_verbosity)
				syslog(LOG_INFO, "name = [%s]; value = [%s]\n",
				       nvp_item->name, nvp_item->value);
			nvp_item = nvp_item->next;
		}
	}
	ctx->nvp_head = &rc_file_nvp_head;
	rc = tse_eval_decision_graph(ctx, mnt_params, &root_param_node,
				     &rc_file_nvp_head);
out_free_allowed_duplicates:
	ad_cursor = allowed_duplicates.next;
	while (ad_cursor) {
		struct tse_name_val_pair *next;
		
		next = ad_cursor->next;
		free(ad_cursor->name);
		free(ad_cursor);
		ad_cursor = next;
	}
out:
	return rc;
}

int tse_process_key_gen_decision_graph(struct tse_ctx *ctx,
					    uint32_t version)
{
	struct tse_name_val_pair nvp_head;
	struct tse_key_mod *key_mod;
	struct val_node *mnt_params;
	int rc;

	if ((mnt_params = malloc(sizeof(struct val_node))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(mnt_params, 0, sizeof(struct val_node));
	if ((rc = tse_register_key_modules(ctx))) {
		syslog(LOG_ERR, "Error attempting to get key module list; "
		       "rc = [%d]\n", rc);
		goto out;
	}
	key_module_select_node.num_transitions = 0;
	key_mod = ctx->key_mod_list_head.next;
	while (key_mod) {
		struct transition_node *trans_node;

		if ((rc =
		     key_mod->ops->get_gen_key_subgraph_trans_node(&trans_node,
								   version))) {
			syslog(LOG_INFO, "Key module [%s] does not have a "
			       "key generation subgraph transition node\n",
			       key_mod->alias);
			/* TODO: Implement key generation linear subgraph */
			key_mod = key_mod->next;
			continue;
		}
		if (trans_node == NULL) {
			syslog(LOG_INFO, "Key module [%s] does not have a "
			       "key generation subgraph transition node\n",
			       key_mod->alias);
			/* TODO: Implement key generation linear subgraph */
			key_mod = key_mod->next;
			continue;
		}
		if ((rc =
		     add_transition_node_to_param_node(&key_module_select_node,
						       trans_node))) {
			syslog(LOG_ERR, "Error attempting to add transition "
			       "node to param node; rc = [%d]\n", rc);
			goto out;
		}
		key_mod = key_mod->next;
	}
	tse_set_exit_param_on_graph(&key_module_select_node,
					 &dummy_param_node);
	memset(&nvp_head, 0, sizeof(struct tse_name_val_pair));
	ctx->nvp_head = &nvp_head;
	key_module_select_node.flags |= TSE_PARAM_FORCE_DISPLAY_NODES;
	tse_eval_decision_graph(ctx, &mnt_params, &key_module_select_node,
				     &nvp_head);
out:
	free(mnt_params);
	return rc;
}
