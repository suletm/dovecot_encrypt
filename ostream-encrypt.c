/* Copyright (c) 2010-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"


#include "ostream-private.h"
#include "ostream-encrypt.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>


#define CHUNK_SIZE (1024*64)
#define PUBFILE   "/usr/local/lib/dovecot/cert.pem"




struct encrypt_ostream {
	struct ostream_private ostream;
	
        int ebuflen;
        EVP_CIPHER_CTX ectx;
        unsigned char iv[EVP_MAX_IV_LENGTH];
        int ekeylen;
        unsigned char *ekey[1];
        EVP_PKEY *pubKey[1];


	struct helper_t helper;

	char evp_header[2 + 4 + 256 + EVP_MAX_IV_LENGTH];
	char outbuf[CHUNK_SIZE];


	unsigned int outbuf_offset, outbuf_used;

	unsigned int flushed:1, header_sent:1, ready4flush:1;
};

/* some prototypes */
EVP_PKEY *ReadPublicKey(const char *certfile);
int do_encrypt(struct encrypt_ostream *encstream, int finish);
int o_stream_encrypt_send_evp_header(struct encrypt_ostream *encstream);
/* end prototypes */

static void o_stream_encrypt_close(struct iostream_private *stream)
{
	struct encrypt_ostream *encstream = (struct encrypt_ostream *)stream;

	o_stream_flush(&encstream->ostream.ostream);
	//EVP_PKEY_free(&encstream->pubKey[0]);
        //free(encstream->ekey[0]);

}

static int o_stream_encrypt_send_outbuf(struct encrypt_ostream *encstream)
{
	ssize_t ret;
	size_t size;

	if (encstream->outbuf_used == 0)
		return 1;

	size = encstream->outbuf_used - encstream->outbuf_offset;
	i_assert(size > 0);
	ret = o_stream_send(encstream->ostream.parent,
			    encstream->outbuf + encstream->outbuf_offset, size);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&encstream->ostream);
		return -1;
	}
	if ((size_t)ret != size) {
		encstream->outbuf_offset += ret;
		return 0;
	}
	encstream->outbuf_offset = 0;
	encstream->outbuf_used = 0;
	return 1;
}

static ssize_t o_stream_encrypt_send_chunk(struct encrypt_ostream *encstream,
			  const void *data, size_t size)
{
	struct helper_t *hlp = &encstream->helper;
	int ret;

	i_assert(encstream->outbuf_used == 0);

        if (!encstream->header_sent)
                o_stream_encrypt_send_evp_header(encstream);

	hlp->next_in = (void *)data;
	hlp->avail_in = size;
	while (hlp->avail_in > 0) {
		if(encstream->ready4flush)
			break;
		if (hlp->ready4output) {
			encstream->outbuf_used = hlp->avail_out;
			if ((ret = o_stream_encrypt_send_outbuf(encstream)) < 0)
				return -1;
			if (ret == 0) {
				/* parent stream's buffer full */
				break;
			}
			hlp->ready4output = FALSE;
			hlp->avail_out = 0;
			hlp->next_out = encstream->outbuf;
			
		}

		switch (do_encrypt(encstream,0)) {
		case  1:
		case  0:
			break;
		case  -1:
			i_fatal("SealUpdate error");
		default:
			i_unreached();
		}
	}
	size -= hlp->avail_in;

	encstream->flushed = FALSE;
	return size;

}

static int o_stream_encrypt_send_flush(struct encrypt_ostream *encstream)
{
	struct helper_t *hlp = &encstream->helper;
	bool done = FALSE;
	int ret;

        if (encstream->ready4flush != 1 && hlp->avail_in !=0) {
                i_assert(encstream->ostream.ostream.last_failed_errno != 0);
                encstream->ostream.ostream.stream_errno =
                        encstream->ostream.ostream.last_failed_errno;
                return -1;
        }


	if (encstream->flushed)
		return 0;

        if (!encstream->header_sent)
                o_stream_encrypt_send_evp_header(encstream);


	encstream->outbuf_used = encstream->helper.avail_out;
	if ((ret = o_stream_encrypt_send_outbuf(encstream)) <= 0)
		return ret;

	encstream->helper.avail_out = 0;
	encstream->helper.next_out = encstream->outbuf;

	i_assert(encstream->outbuf_used == 0);
	do {
                if (hlp->avail_out > 0) {
                        encstream->outbuf_used = hlp->avail_out;
                        if ((ret = o_stream_encrypt_send_outbuf(encstream)) <= 0)
                                return ret;
                        if (done)
                                break;
                }


		if(done)
			break;
		ret = do_encrypt(encstream, 1);	
		switch (ret) {
			case 1:
				done = TRUE;
				break;
			case -1:
				i_fatal("EVP_SealFinal error");
		default:
			i_fatal("finish=1: ret: %d\n", ret);
			i_unreached();
		}
	} while (encstream->helper.avail_out != sizeof(encstream->outbuf));

	encstream->flushed = TRUE;
	return 0;
}

static int o_stream_encrypt_flush(struct ostream_private *stream)
{
	struct encrypt_ostream *encstream = (struct encrypt_ostream *)stream;
	int ret;

	if (o_stream_encrypt_send_flush(encstream) < 0)
		return -1;

	ret = o_stream_flush(stream->parent);
	if (ret < 0)
		o_stream_copy_error_from_parent(stream);
	return ret;
}

static ssize_t
o_stream_encrypt_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct encrypt_ostream *encstream = (struct encrypt_ostream *)stream;
	ssize_t ret, bytes = 0;
	unsigned int i;

	if ((ret = o_stream_encrypt_send_outbuf(encstream)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		return ret;
	}

	for (i = 0; i < iov_count; i++) {
		ret = o_stream_encrypt_send_chunk(encstream, iov[i].iov_base,
						iov[i].iov_len);
		if (ret < 0)
			return -1;
		bytes += ret;
		if ((size_t)ret != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += bytes;

	/* avail_in!=0 check is used to detect errors. if it's non-zero here
	   it simply means we didn't send all the data */
	/* XX we can have last bytes that need to be padded by SealFinal, so avail_in can be > zero */
	//encstream->helper.avail_in = 0;
	return bytes;
}
struct ostream  *o_stream_create_encrypt(struct ostream *output)
{
	struct encrypt_ostream *encstream;
	int net_ekeylen;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	char *p;


	encstream = i_new(struct encrypt_ostream, 1);
	encstream->ostream.sendv = o_stream_encrypt_sendv;
	encstream->ostream.flush = o_stream_encrypt_flush;
	encstream->ostream.iostream.close = o_stream_encrypt_close;

        memset(iv, '\0', sizeof(iv));

        encstream->pubKey[0] = ReadPublicKey(PUBFILE);

	if(!encstream->pubKey[0])
	{
		i_fatal("Ccould not load public key");
	}


        encstream->ekey[0] = malloc(EVP_PKEY_size(encstream->pubKey[0]));
	if(!encstream->ekey)
	{
		EVP_PKEY_free(encstream->pubKey[0]);
		i_fatal("Ccould not malloc space for ekey");
	}


	/*  XXX: here we must initialize RNG because random symmetric keys are generated during SealInit */
	if( EVP_SealInit(&encstream->ectx, EVP_des_ede3_cbc(), encstream->ekey, &encstream->ekeylen, iv, encstream->pubKey, 1) == -1)
	{
                EVP_PKEY_free(encstream->pubKey[0]);
		free(encstream->ekey[0]);
		i_fatal("Ccould not SealInit()");
	}

	/* construct envelope header */
	net_ekeylen = htonl(encstream->ekeylen);

	p = (char *) &encstream->evp_header;
	*p = 0x13;
	p++;
	*p  = 0x37;
	p++;
	memcpy(p, (char *)&net_ekeylen, sizeof(net_ekeylen)); 

	p = p + sizeof(net_ekeylen);
	memcpy(p, encstream->ekey[0], encstream->ekeylen);

	p = p + encstream->ekeylen;
	memcpy(p, &iv, sizeof(iv)); 
	

	encstream->helper.next_out = encstream->outbuf;
	encstream->helper.avail_out = 0;
	encstream->helper.ready4output = FALSE;
	encstream->header_sent = FALSE;
	return o_stream_create(&encstream->ostream, output);
}

EVP_PKEY *ReadPublicKey(const char *certfile)
{
  FILE *fp = fopen (certfile, "r");
  X509 *x509;
  EVP_PKEY *pkey;

  if (!fp)
     return  NULL;

  x509 = PEM_read_X509(fp, NULL, 0, NULL);

  if (x509 == NULL)
  {
     fprintf(stderr, "Coould not PEM_read_X509\n");
     return  NULL;
  }

  fclose (fp);

  pkey=X509_extract_key(x509);

  X509_free(x509);

  if (pkey == NULL)
  {
    fprintf(stderr, "pkey is NULL. Something went wrong\n");
    return NULL;
  }

  return pkey;
}


int do_encrypt(struct encrypt_ostream *encstream, int finish)
{
	struct helper_t *hlp = &encstream->helper;
	fprintf(stderr, "DO_ENCRYPT ENTERED\n");
	int pt_len,elen;

	if(!encstream->header_sent)
	{
		o_stream_encrypt_send_evp_header(encstream);
		encstream->header_sent = TRUE;
	}
	

	/* divide blocks so that minimum block is 256 bytes, not less*/
	if(hlp->avail_in > 256)
		pt_len = 256;
	else 
		pt_len = hlp->avail_in;	

	if(!finish)
	{
		if(!EVP_SealUpdate(&encstream->ectx, (unsigned char*) hlp->next_out, &elen, 
						(unsigned char *) hlp->next_in, pt_len))
			return -1;
		if(elen == 0)
		{
			/* ready for calling flush with SealFinal that will take care of padding */
			encstream->ready4flush = TRUE;
			return 0;
		}
		hlp->avail_in = hlp->avail_in - pt_len;
		hlp->next_in  = hlp->next_in + pt_len;

		hlp->avail_out = hlp->avail_out + elen;
		hlp->next_out  = hlp->next_out + elen;
	} else
	{
		if(!EVP_SealFinal(&encstream->ectx, (unsigned char *) hlp->next_out, &elen))
			return -1;
		fprintf(stderr, "SealFinal\n");
		hlp->avail_in = hlp->avail_in - pt_len;
		hlp->avail_out = hlp->avail_out + elen;
	}	

	hlp->ready4output=TRUE;
	return 1;
}	

int o_stream_encrypt_send_evp_header(struct encrypt_ostream *encstream)
{
        ssize_t ret;

        ret = o_stream_send(encstream->ostream.parent, encstream->evp_header,
                            sizeof(encstream->evp_header));
        if ((size_t)ret != sizeof(encstream->evp_header)) {
                o_stream_copy_error_from_parent(&encstream->ostream);
                return -1;
        }
        encstream->header_sent = TRUE;
        return 0;
}


