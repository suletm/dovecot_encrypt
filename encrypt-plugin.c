/* Copyright (c) 2012 Dovecot authors, Tofig, Roman */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "mail-user.h"
#include "dbox-single/sdbox-storage.h"
#include "dbox-multi/mdbox-storage.h"
#include "maildir/maildir-storage.h"
#include "index-storage.h"
#include "index-mail.h"
#include "istream-encrypt.h"
#include "ostream-encrypt.h"
#include "encrypt-plugin.h"
#include <stdio.h>

#include <stdlib.h>
#include <fcntl.h>


#define ENCRYPT_CONTEXT(obj) \
	MODULE_CONTEXT(obj, encrypt_storage_module)
#define ENCRYPT_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, encrypt_mail_module)
#define ENCRYPT_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, encrypt_user_module)


#define MAX_INBUF_SIZE (1024*1024)

struct encrypt_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct mail *tmp_mail;
};

struct encrypt_user {
	union mail_user_module_context module_ctx;

	const struct encrypt_handler *save_handler;
};

const char *encrypt_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(encrypt_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(encrypt_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(encrypt_mail_module, &mail_module_register);

static bool is_encrypted(struct istream *input)
{
	const unsigned char *data;
	size_t size;

	/* Peek in to the stream and see if it looks like it's compressed
	   (based on its header). This also means that users can try to exploit
	   security holes in the uncompression library by APPENDing a specially
	   crafted mail. So let's hope zlib is free of holes. */
	if (i_stream_read_data(input, &data, &size, 1) <= 0)
		return FALSE;
	i_assert(size >= 2);

	/* magic numbers to detect openssl envelope */
	return data[0] == 0x13 && data[1] == 0x37;
}


const struct encrypt_handler *encrypt_find_encrypt_handler(const char *name)
{
	unsigned int i;

	for (i = 0; encrypt_handlers[i].name != NULL; i++) {
		if (strcmp(name, encrypt_handlers[i].name) == 0)
			return &encrypt_handlers[i];
	}
	return NULL;
}

static const struct encrypt_handler *encrypt_get_encrypt_handler(struct istream *input)
{
	unsigned int i;

	for (i = 0; encrypt_handlers[i].name != NULL; i++) {
		if (encrypt_handlers[i].is_encrypted!= NULL &&
		    encrypt_handlers[i].is_encrypted(input))
			return &encrypt_handlers[i];
	}
	return NULL;
}

static const struct encrypt_handler *encrypt_get_encrypt_handler_ext(const char *name)
{
	unsigned int i, len, name_len = strlen(name);

	for (i = 0; encrypt_handlers[i].name != NULL; i++) {
		if (encrypt_handlers[i].ext == NULL)
			continue;

		len = strlen(encrypt_handlers[i].ext);
		if (name_len > len &&
		    strcmp(name + name_len - len, encrypt_handlers[i].ext) == 0)
			return &encrypt_handlers[i];
	}
	return NULL;
}

static int encrypt_istream_opened(struct mail *_mail, struct istream **stream)
{
	struct encrypt_user *encuser = ENCRYPT_USER_CONTEXT(_mail->box->storage->user);
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *encmail = ENCRYPT_MAIL_CONTEXT(mail);
	struct istream *input;
	const struct encrypt_handler *handler;

	/* don't uncompress input when we are reading a mail that we're just
	   in the middle of saving, and we didn't do the compression ourself.
	   in such situation we're probably checking if the user-given input
	   looks compressed */
	if (_mail->saving && encuser->save_handler == NULL)
		return encmail->super.istream_opened(_mail, stream);

	handler = encrypt_get_encrypt_handler(*stream);
	if (handler != NULL) {
		if (handler->create_istream == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"encrypt plugin: Detected %s encryption"
				"but support not compiled in", handler->ext);
			return -1;
		}

		input = *stream;
		*stream = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
	}
	return encmail->super.istream_opened(_mail, stream);
}

static void encrypt_mail_allocated(struct mail *_mail)
{
	struct encrypt_transaction_context *enct = ENCRYPT_CONTEXT(_mail->transaction);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *encmail;

	if (enct == NULL)
		return;

	encmail = p_new(mail->pool, union mail_module_context, 1);
	encmail->super = *v;
	mail->vlast = &encmail->super;

	v->istream_opened = encrypt_istream_opened;
	MODULE_CONTEXT_SET_SELF(mail, encrypt_mail_module, encmail);
}

static struct mailbox_transaction_context *
encrypt_mailbox_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct encrypt_transaction_context *enct;

	t = encbox->super.transaction_begin(box, flags);

	enct = i_new(struct encrypt_transaction_context, 1);

	MODULE_CONTEXT_SET(t, encrypt_storage_module, enct);
	return t;
}

static void
encrypt_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(t->box);
	struct encrypt_transaction_context *enct = ENCRYPT_CONTEXT(t);

	if (enct->tmp_mail != NULL)
		mail_free(&enct->tmp_mail);

	encbox->super.transaction_rollback(t);
	i_free(enct);
}

static int
encrypt_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				struct mail_transaction_commit_changes *changes_r)
{
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(t->box);
	struct encrypt_transaction_context *enct = ENCRYPT_CONTEXT(t);
	int ret;

	if (enct->tmp_mail != NULL)
		mail_free(&enct->tmp_mail);

	ret = encbox->super.transaction_commit(t, changes_r);
	i_free(enct);
	return ret;
}

static int
encrypt_mail_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct encrypt_transaction_context *enct = ENCRYPT_CONTEXT(t);
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(t->box);

	if (ctx->dest_mail == NULL) {
		if (enct->tmp_mail == NULL) {
			enct->tmp_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE,
						  NULL);
		}
		ctx->dest_mail = enct->tmp_mail;
	}

	return encbox->super.save_begin(ctx, input);
}

static int encrypt_mail_save_finish(struct mail_save_context *ctx)
{
	struct mailbox *box = ctx->transaction->box;
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(box);
	struct istream *input;

	if (encbox->super.save_finish(ctx) < 0)
		return -1;

	if (mail_get_stream(ctx->dest_mail, NULL, NULL, &input) < 0)
		return -1;

	if (encrypt_get_encrypt_handler(input) != NULL) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Encrypting mails already encrypted by client isn't supported");
		return -1;
	}
	return 0;
}

static int
encrypt_mail_save_encrypt_begin(struct mail_save_context *ctx,
			      struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct encrypt_user *encuser = ENCRYPT_USER_CONTEXT(box->storage->user);
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(box);
	struct ostream *output;

	if (encbox->super.save_begin(ctx, input) < 0)
		return -1;

	output = encuser->save_handler->create_ostream(ctx->output);
	o_stream_unref(&ctx->output);
	ctx->output = output;
	o_stream_cork(ctx->output);
	return 0;
}

static void
encrypt_permail_alloc_init(struct mailbox *box, struct mailbox_vfuncs *v)
{
	struct encrypt_user *encuser = ENCRYPT_USER_CONTEXT(box->storage->user);

	v->transaction_begin = encrypt_mailbox_transaction_begin;
	v->transaction_rollback = encrypt_mailbox_transaction_rollback;
	v->transaction_commit = encrypt_mailbox_transaction_commit;
	if (encuser->save_handler == NULL) {
		v->save_begin = encrypt_mail_save_begin;
		v->save_finish = encrypt_mail_save_finish;
	} else {
		v->save_begin = encrypt_mail_save_encrypt_begin;
	}
}

static int encrypt_mailbox_open_input(struct mailbox *box)
{
	const struct encrypt_handler *handler;
	struct istream *input;
	struct stat st;
	int fd;

	handler = encrypt_get_encrypt_handler_ext(box->name);
	if (handler == NULL || handler->create_istream == NULL)
		return 0;

	if (mail_storage_is_mailbox_file(box->storage)) {
		/* looks like a compressed single file mailbox. we should be
		   able to handle this. */
		const char *box_path = mailbox_get_path(box);

		fd = open(box_path, O_RDONLY);
		if (fd == -1) {
			/* let the standard handler figure out what to do
			   with the failure */
			return 0;
		}
		if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
			(void)close(fd);
			return 0;
		}
		input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
		i_stream_set_name(input, box_path);
		box->input = handler->create_istream(input, TRUE);
		i_stream_unref(&input);
		box->flags |= MAILBOX_FLAG_READONLY;
	}
	return 0;
}

static int encrypt_mailbox_open(struct mailbox *box)
{
	union mailbox_module_context *encbox = ENCRYPT_CONTEXT(box);

	if (box->input == NULL &&
	    (box->storage->class_flags &
	     MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) != 0) {
		if (encrypt_mailbox_open_input(box) < 0)
			return -1;
	}

	return encbox->super.open(box);
}

static void encrypt_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *encbox;

	encbox = p_new(box->pool, union mailbox_module_context, 1);
	encbox->super = *v;
	box->vlast = &encbox->super;
	v->open = encrypt_mailbox_open;

	MODULE_CONTEXT_SET_SELF(box, encrypt_storage_module, encbox);

	if (strcmp(box->storage->name, MAILDIR_STORAGE_NAME) == 0 ||
	    strcmp(box->storage->name, MDBOX_STORAGE_NAME) == 0 ||
	    strcmp(box->storage->name, SDBOX_STORAGE_NAME) == 0)
		encrypt_permail_alloc_init(box, v);
}

static void encrypt_mail_user_created(struct mail_user *user)
{
	struct encrypt_user *encuser;
	const char *name;

	encuser = p_new(user->pool, struct encrypt_user, 1);

	name = mail_user_plugin_getenv(user, "encrypt_save");
	if (name != NULL && *name != '\0') {
		encuser->save_handler = encrypt_find_encrypt_handler(name);
		if (encuser->save_handler == NULL)
			i_error("encrypt_save: Unknown handler: %s", name);
	}
	MODULE_CONTEXT_SET(user, encrypt_user_module, encuser);
}

static struct mail_storage_hooks encrypt_mail_storage_hooks = {
	.mail_user_created = encrypt_mail_user_created,
	.mailbox_allocated = encrypt_mailbox_allocated,
	.mail_allocated = encrypt_mail_allocated
};

void encrypt_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &encrypt_mail_storage_hooks);
}

void encrypt_plugin_deinit(void)
{
	mail_storage_hooks_remove(&encrypt_mail_storage_hooks);
}

const struct encrypt_handler encrypt_handlers[] = {
	{ "encrypt", NULL, is_encrypted, i_stream_create_encrypt, o_stream_create_encrypt},
	{ NULL, NULL, NULL, NULL, NULL }
};
