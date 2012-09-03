#ifndef ENCRYPT_PLUGIN_H
#define ENCRYPT_PLUGIN_H

/* struct that keeps mapping of file extensions -> [i]|[o]stream */

struct encrypt_handler {
        const char *name;  // name of corresponding module
        const char *ext;   // file extension
        bool (*is_encrypted)(struct istream *input); 
        struct istream *(*create_istream)(struct istream *input, bool log_errors); // corresponding input stream
        struct ostream *(*create_ostream)(struct ostream *output); // corresponding output stream
};


extern const struct encrypt_handler encrypt_handlers[];

const struct encrypt_handler *encrypt_find_encrypt_handler(const char *name);


void encrypt_plugin_init(struct module *module);
void encrypt_plugin_deinit(void);




#define fail_if_err(err)                                      \
do                                                            \
{                                                             \
 if (err)                                                     \
 {                                                            \
    i_fatal("GPGME error: %s, %s\n", gpgme_strsource (err),   \
    gpgme_strerror (err));                                    \
  }                                                           \
}                                                             \
while (0)

#endif
