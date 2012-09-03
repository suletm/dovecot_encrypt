#ifndef OSTREAM_ENCRYPT_H
#define OSTREAM_ENCRYPT_H

struct ostream *o_stream_create_encrypt(struct ostream *output);

struct helper_t
{
  /* number of available bytes to input into crypto engine for encryption */
  unsigned int avail_in;
  /* number of encrypted bytes returned by crypto engine */
  unsigned int avail_out;
  /* pointer for encrypted data that came out of crypto engine */
  char *next_out;
  /* pointer for plaintext data that is going to be fed to a crypto engine */
  char *next_in;
  unsigned int ready4output;
  unsigned int ready4flush; 
} ;


#endif
