#ifndef CPPWRAPPER_H
#define CPPWRAPPER_H

#include <cmath>

using namespace std;
using namespace seal;

namespace wrapper {
    class Wrapper {
        public:
            /* Constructor & Destructor */
            Wrapper();
            Wrapper(
                string scheme,
                int security_level,
                int poly_modulus_degree,
                int coeff_modulus,
                int plain_modulus
            );
            ~Wrapper();

            /* Methods */
            // logging
            void print_seal_version();
            void print_parameters();
            void print_allocated_memory();
            // pointers management
            void clear_all_stored_pointers();
            void clear_plaintext(string plaintext_name);
            void clear_ciphertext(string ciphertext_name);
            // encoding
            string plaintext_to_string(string plaintext_name);
            // integer encoder
            void init_integer_encoder();
            string integer_encoder(int integer, string plaintext_name);
            int64_t integer_decoder(string plaintext_pointer);
            // encrypt & decrypt
            int decryptor_invariant_noise_budget(string ciphertext_name);
            string encryptor_encrypt(string plaintext_name, string ciphertext_name);
            string decryptor_decrypt(string ciphertext_name, string plaintext_name);
            // evaluator
            void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2);

        private:
            /* Members */
            map<string, Plaintext> plaintext_map;
            map<string, Ciphertext> ciphertext_map;
            shared_ptr<SEALContext> context;
            IntegerEncoder*integerEncoder;
            Encryptor*encryptor;
            Evaluator*evaluator;
            Decryptor*decryptor;

             /* Methods */
            Plaintext& get_plaintext(string plaintext_name);
            Ciphertext& get_ciphertext(string ciphertext_name);
    };
}

#endif