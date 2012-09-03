/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"


#include "istream-private.h"
#include "istream-encrypt.h"
#include <ostream-encrypt.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <unistd.h>
#include <arpa/inet.h>



//#define CHUNK_SIZE (1024*64)
#define CHUNK_SIZE (100)
#define PRIVFILE "/usr/local/lib/dovecot/privkey.pem"


struct encrypt_istream {
	struct istream_private istream;

        unsigned int buflen;
        EVP_CIPHER_CTX ectx;
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char *encryptKey;
        int ekeylen;
        EVP_PKEY *privateKey;

	struct i_helper_t helper;
	uoff_t eof_offset, stream_size;
	size_t prev_size, high_pos;
	struct stat last_parent_statbuf;
	size_t  header_size;

	unsigned int log_errors:1;
	unsigned int marked:1;
	unsigned int enc_closed:1;
	unsigned int header_read:1;
};

/* prototypes */
int do_decrypt(struct encrypt_istream *encstream, int finish);
EVP_PKEY *ReadPrivateKey(const char *keyfile);
static int i_stream_encrypt_read_header(struct encrypt_istream *encstream);
static void i_stream_encrypt_sync(struct istream_private *stream);

/**/

static void i_stream_encrypt_close(struct iostream_private *stream)
{
	struct encrypt_istream *encstream = (struct encrypt_istream *)stream;

 	fprintf(stderr, "i_stream_encrypt_close entered\n");	
	if (!encstream->enc_closed) {
		//do_decrypt(encstream, 1);
		encstream->enc_closed = TRUE;
	}
}

static void encrypt_read_error(struct encrypt_istream *encstream, const char *error)
{
	i_error("encrypt.read(%s): %s at %"PRIuUOFF_T,
		i_stream_get_name(&encstream->istream.istream), error,
		encstream->istream.abs_start_offset +
		encstream->istream.istream.v_offset);
}

static ssize_t i_stream_encrypt_read(struct istream_private *stream)
{
	struct encrypt_istream *encstream = (struct encrypt_istream *)stream;
	const unsigned char *data;
	uoff_t high_offset;
	size_t size;
	int ret;



        /* we must read envelope header in order to get our symmetric key and all related data */
	
	if(!encstream->header_read)
	{
		/* sync stat structure first because we need actual st_size while determining 
		 * when to execute EVP_OpenFinal
		 */
		i_stream_encrypt_sync(stream);
        
		ret = i_stream_encrypt_read_header(encstream);
		if( ret < 0 )
			i_fatal("Could not read envelope header");
		encstream->header_size = encstream->prev_size;
		encstream->helper.avail_in_pos = encstream->header_size;

		/* now we should have header bits ready in encstream members
		 * proceed with EVP_OpenInit
		 */

		if(! EVP_OpenInit(&encstream->ectx,
			   EVP_des_ede3_cbc(),
			   encstream->encryptKey,
			   encstream->ekeylen,
			   (unsigned char*) &encstream->iv,
			   encstream->privateKey)) {
			/* XXX Free everything not needed. Please complete this */
			EVP_PKEY_free(encstream->privateKey);
			i_fatal("Could not OpenInit()");
		}
		encstream->header_read=TRUE;
	}



	high_offset = stream->istream.v_offset + (stream->pos - stream->skip);
	if (encstream->eof_offset == high_offset) {
		i_assert(encstream->high_pos == 0 ||
			 encstream->high_pos == stream->pos);
		stream->istream.eof = TRUE;
		return -1;
	}

	if (stream->pos < encstream->high_pos) {
		/* we're here because we seeked back within the read buffer. */
		ret = encstream->high_pos - stream->pos;
		stream->pos = encstream->high_pos;
		encstream->high_pos = 0;

		if (encstream->eof_offset != (uoff_t)-1) {
			high_offset = stream->istream.v_offset +
				(stream->pos - stream->skip);
			i_assert(encstream->eof_offset == high_offset);
			stream->istream.eof = TRUE;
		}
		return ret;
	}
	encstream->high_pos = 0;

	if (stream->pos + CHUNK_SIZE > stream->buffer_size) {
		/* try to keep at least CHUNK_SIZE available */
		if (!encstream->marked && stream->skip > 0) {
			/* don't try to keep anything cached if we don't
			   have a seek mark. */
			i_stream_compress(stream);
		}
		if (stream->max_buffer_size == 0 ||
		    stream->buffer_size < stream->max_buffer_size)
			i_stream_grow_buffer(stream, CHUNK_SIZE);

		if (stream->pos == stream->buffer_size) {
			if (stream->skip > 0) {
				/* lose our buffer cache */
				i_stream_compress(stream);
			}

			if (stream->pos == stream->buffer_size)
				return -2; /* buffer full */
		}
	}

	if (encstream->helper.avail_in == 0) {
		/* need to read more data. try to read a full CHUNK_SIZE */
		i_stream_skip(stream->parent, encstream->prev_size);
		if (i_stream_read_data(stream->parent, &data, &size,
				       CHUNK_SIZE-1) == -1 && size == 0) {
			if (stream->parent->stream_errno != 0) {
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			} else {
				i_assert(stream->parent->eof);
				if (encstream->log_errors) {
					encrypt_read_error(encstream,
							 "unexpected EOF");
				}
				stream->istream.stream_errno = EINVAL;
			}
			return -1;
		}
		encstream->prev_size = size;
		if (size == 0) {
			/* no more input */
			i_assert(!stream->istream.blocking);
			return 0;
		}

		encstream->helper.next_in = (char *)data;
		encstream->helper.avail_in = size;
	}

	size = stream->buffer_size - stream->pos;
	encstream->helper.next_out = (char *)stream->w_buffer + stream->pos;
	encstream->helper.avail_out = size;

	ret = do_decrypt(encstream,0);

	size -= encstream->helper.avail_out;
	stream->pos += size;

	switch (ret) {
	case EVP_OK:
		break;
	case EVP_ERROR:
		if (encstream->log_errors)
			encrypt_read_error(encstream, "corrupted data");
		stream->istream.stream_errno = EINVAL;
		return -1;
	default:
		i_fatal("(unreachable) do_decrypt() failed with %d", ret);
	}
	if (size == 0) {
		/* read more input */
		return i_stream_encrypt_read(stream);
	}
	return size;
}

static void i_stream_encrypt_init(struct encrypt_istream *encstream)
{
	sleep(20);

	encstream->privateKey = ReadPrivateKey(PRIVFILE);

        if(!encstream->privateKey)
                i_fatal("Ccould not load private key");
	encstream->header_read = 0;

	/* 
	* we must read envelope header in order to get our symmetric key,iv and etc
	* but it is not possible here, as istream->parent has not been initialized by the 
	* plugin subsystem yet, therefore we do it in *read* part 
	*/

}

static void i_stream_encrypt_reset(struct encrypt_istream *encstream)
{
	struct istream_private *stream = &encstream->istream;

	i_stream_seek(stream->parent, stream->parent_start_offset);
	encstream->eof_offset = (uoff_t)-1;
	encstream->helper.next_in = NULL;
	encstream->helper.avail_in = 0;

	stream->parent_expected_offset = stream->parent_start_offset;
	stream->skip = stream->pos = 0;
	stream->istream.v_offset = 0;
	encstream->high_pos = 0;
	encstream->prev_size = 0;

	encstream->helper.avail_in_pos = 0;

}

static void
i_stream_encrypt_seek(struct istream_private *stream, uoff_t v_offset, bool mark)
{
	struct encrypt_istream *encstream = (struct encrypt_istream *) stream;
	uoff_t start_offset = stream->istream.v_offset - stream->skip;

	if (v_offset < start_offset) {
		/* have to seek backwards */
		i_stream_encrypt_reset(encstream);
		start_offset = 0;
	} else if (encstream->high_pos != 0) {
		stream->pos = encstream->high_pos;
		encstream->high_pos = 0;
	}

	if (v_offset <= start_offset + stream->pos) {
		/* seeking backwards within what's already cached */
		stream->skip = v_offset - start_offset;
		stream->istream.v_offset = v_offset;
		encstream->high_pos = stream->pos;
		stream->pos = stream->skip;
	} else {
		/* read and cache forward */
		do {
			size_t avail = stream->pos - stream->skip;

			if (stream->istream.v_offset + avail >= v_offset) {
				i_stream_skip(&stream->istream,
					      v_offset -
					      stream->istream.v_offset);
				break;
			}

			i_stream_skip(&stream->istream, avail);
		} while (i_stream_read(&stream->istream) >= 0);

		if (stream->istream.v_offset != v_offset) {
			/* some failure, we've broken it */
			if (stream->istream.stream_errno != 0) {
				i_error("encrypt.seek(%s) failed: %s",
					i_stream_get_name(&stream->istream),
					strerror(stream->istream.stream_errno));
				i_stream_close(&stream->istream);
			} else {
				/* unexpected EOF. allow it since we may just
				   want to check if there's anything.. */
				i_assert(stream->istream.eof);
			}
		}
	}

	if (mark)
		encstream->marked = TRUE;
}

static const struct stat *
i_stream_encrypt_stat(struct istream_private *stream, bool exact)
{
	struct encrypt_istream *encstream = (struct encrypt_istream *) stream;
	const struct stat *st;
	size_t size;

	st = i_stream_stat(stream->parent, exact);
	if (st == NULL)
		return NULL;

	/* when exact=FALSE always return the parent stat's size, even if we
	   know the exact value. this is necessary because otherwise e.g. mbox
	   code can see two different values and think that a compressed mbox
	   file keeps changing. */
	if (!exact)
		return st;

	stream->statbuf = *st;
	if (encstream->stream_size == (uoff_t)-1) {
		uoff_t old_offset = stream->istream.v_offset;

		do {
			(void)i_stream_get_data(&stream->istream, &size);
			i_stream_skip(&stream->istream, size);
		} while (i_stream_read(&stream->istream) > 0);

		i_stream_seek(&stream->istream, old_offset);
		if (encstream->stream_size == (uoff_t)-1)
			return NULL;
	}
	stream->statbuf.st_size = encstream->stream_size;
	return &stream->statbuf;
}

static void i_stream_encrypt_sync(struct istream_private *stream)
{
	struct encrypt_istream *encstream = (struct encrypt_istream *) stream;
	const struct stat *st;

	st = i_stream_stat(stream->parent, FALSE);
	if (st != NULL) {
		if (memcmp(&encstream->last_parent_statbuf,
			   st, sizeof(*st)) == 0) {
			/* a compressed file doesn't change unexpectedly,
			   don't clear our caches unnecessarily */
			return;
		}
		encstream->last_parent_statbuf = *st;
	}
	i_stream_encrypt_reset(encstream);
}

struct istream *i_stream_create_encrypt(struct istream *input, bool log_errors)
{
	struct encrypt_istream *encstream;

	encstream = i_new(struct encrypt_istream, 1);
	encstream->eof_offset = (uoff_t)-1;
	encstream->stream_size = (uoff_t)-1;
	encstream->helper.avail_in_pos = 0;

	encstream->log_errors = log_errors;

	i_stream_encrypt_init(encstream);

	encstream->istream.iostream.close = i_stream_encrypt_close;
	encstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	encstream->istream.read = i_stream_encrypt_read;
	encstream->istream.seek = i_stream_encrypt_seek;
	encstream->istream.stat = i_stream_encrypt_stat;
	encstream->istream.sync = i_stream_encrypt_sync;

	encstream->istream.istream.readable_fd = FALSE;
	encstream->istream.istream.blocking = input->blocking;
	encstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&encstream->istream, input,
			       i_stream_get_fd(input));
}


static int i_stream_encrypt_read_header(struct encrypt_istream *encstream)
{
	struct istream_private *stream = &encstream->istream;
        const unsigned char *data;
        size_t size;
        unsigned int pos=0;
        int ret;

        ret = i_stream_read_data(stream->parent, &data, &size,
                                 encstream->prev_size);
        if (size == encstream->prev_size) {
                if (ret == -1) {
                        if (encstream->log_errors)
                                encrypt_read_error(encstream, "missing openssl magic header");
                        stream->istream.stream_errno = EINVAL;
                }
                return ret;
        }
        encstream->prev_size = size;

	/* 2 first bytes are magic 0x13 0x37 */
        if (size < 2)
                return 0;

        if (data[0] != 0x13 || data[1] != 0x37 ) {
                /* missing gzip magic header */
                if (encstream->log_errors) {
                        encrypt_read_error(encstream, "wrong magic in header "
                                        "(not an SSL EVP encrypted file?)");
                }
                stream->istream.stream_errno = EINVAL;
                return -1;
        }
	
	/* get envelope settings located right after the magic */
	data++; data++;
	pos++; pos++;
	
	memcpy(&encstream->ekeylen,data, sizeof(encstream->ekeylen));
        encstream->ekeylen = ntohl(encstream->ekeylen);


        if (encstream->ekeylen != EVP_PKEY_size(encstream->privateKey))
        {
                EVP_PKEY_free(encstream->privateKey);
                if (encstream->log_errors) {
                        encrypt_read_error(encstream, "key length mismatch"
                                        "(ekeylen size is not equal to privkey size)");
                }
                stream->istream.stream_errno = EINVAL;
                return -1;
        }

	data = data + sizeof(encstream->ekeylen);
	pos = pos + sizeof(encstream->ekeylen);

	
	
	encstream->encryptKey = i_new(unsigned char, 1);
        memcpy(encstream->encryptKey, data, encstream->ekeylen);
	data = data + encstream->ekeylen;
	pos = pos + encstream->ekeylen;

        memcpy(&encstream->iv, data, sizeof(encstream->iv));
	pos = pos + sizeof(encstream->iv);

	encstream->prev_size = pos;
    //    i_stream_skip(stream->parent, pos);
        return 1;
}

int do_decrypt(struct encrypt_istream *encstream, int finish)
{
	struct i_helper_t *hlp = &encstream->helper;
        int pt_len,elen,ret;


        fprintf(stderr, "DO_DECRYPT ENTERED. st_size: %d\n", (int) encstream->last_parent_statbuf.st_size);


	
	/* divide blocks so that minimum block is 256 bytes, not less*/
	if(hlp->avail_in > 256)
		elen = 256;
	else
		elen = hlp->avail_in;
	
	hlp->avail_in_pos = hlp->avail_in_pos + elen;

	if(!finish)
	{
		ret = EVP_OpenUpdate(&encstream->ectx, (unsigned char*) hlp->next_out, &pt_len, 
				     (unsigned char *) hlp->next_in, elen);
		if (ret == 0)
			/* something bad happened. return with error */
			return EVP_ERROR;
		if(pt_len == 0)
		{
			/* this is the final block */	
			return EVP_FINAL_BLOCK;
		} else {
			hlp->next_in = hlp->next_in + elen;
         		hlp->avail_in = hlp->avail_in - elen;

			hlp->avail_out = hlp->avail_out - pt_len;
			hlp->next_out  = hlp->next_out + pt_len;

			/* we are at the end of the parent stream */
			if(hlp->avail_in_pos == encstream->last_parent_statbuf.st_size)
			{
				/* we need to call EVP_OpenFinal */ 
				ret = EVP_OpenFinal(&encstream->ectx, (unsigned char*) hlp->next_out, &pt_len);
				if(ret)
				{
					hlp->avail_out = hlp->avail_out - pt_len;
					hlp->next_out  = hlp->next_out + pt_len;
					hlp->next_out = '\0';
					return EVP_OK;
				}
				else
					i_fatal("Could not issue EVP_OpenFinal");
			}

			return EVP_OK;
		}
	}
	return 10;
}

EVP_PKEY *ReadPrivateKey(const char *keyfile)
{
	FILE *fp = fopen(keyfile, "r");
	EVP_PKEY *pkey;

	if (!fp)
		return NULL;

	pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);

	fclose (fp);

  	if (pkey == NULL) 
		ERR_print_errors_fp (stderr);   

	return pkey;
}

