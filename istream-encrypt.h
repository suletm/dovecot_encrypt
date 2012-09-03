#ifndef ISTREAM_ENCRYPT_H
#define ISTREAM_ENCRYPT_H


#define EVP_ERROR -1
#define EVP_OK 1
#define EVP_FINAL_BLOCK 0

struct istream *i_stream_create_encrypt(struct istream *input, bool log_errors);

struct i_helper_t
{
  /* number of available bytes to input into crypto engine for encryption */
  unsigned int avail_in;
  /* number of encrypted bytes returned by crypto engine */
  unsigned int avail_out;
  /* pointer for encrypted data that came out of crypto engine */
  char *next_out;
  /* pointer for plaintext data that is going to be fed to a crypto engine */
  char *next_in;
  /* position for EVP_OpenFInal() */
  unsigned int avail_in_pos;
  bool ready4flush:1;
} ;




#endif
