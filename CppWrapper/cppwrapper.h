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
            // plaintext
            string plaintext_to_string(string plaintext_name);
            string plaintext_create(string expression, string plaintext_name);
            // ciphertext
            int ciphertext_size(string ciphertext_name);
            // integer encoder
            void init_integer_encoder();
            string integer_encoder(int integer, string plaintext_name);
            int64_t integer_decoder(string plaintext_pointer);
            // batch encoder
            void init_batch_encoder();
            // encrypt & decrypt
            int decryptor_invariant_noise_budget(string ciphertext_name);
            string encryptor_encrypt(string plaintext_name, string ciphertext_name);
            string decryptor_decrypt(string ciphertext_name, string plaintext_name);
            // evaluator
            void evaluator_relinearize_inplace(string ciphertext_name);
            void evaluator_negate_inplace(string ciphertext_name);
            void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2);
            void evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2);
            void evaluator_square_inplace(string ciphertext_name);
            // relinearization
            void relinearization_generate_keys(int decomposition_bit_count, size_t count);
            int relinearization_dbc_max();
            int relinearization_dbc_min();
            // batching
            bool batching_is_enabled();
            void batching_generate_galois_keys(int decomposition_bit_count);

        private:
            /* Members */
            map<string, Plaintext> plaintext_map;
            map<string, Ciphertext> ciphertext_map;
            shared_ptr<SEALContext> context;
            IntegerEncoder*integerEncoder;
            BatchEncoder*batchEncoder;
            Encryptor*encryptor;
            Evaluator*evaluator;
            Decryptor*decryptor;
            KeyGenerator*keygen;
            RelinKeys relinearize_keys;
            GaloisKeys galois_keys;

            /* Methods */
            void check_plaintext_name_exist(string plaintext_name);
            void check_ciphertext_name_exist(string ciphertext_name);
            void check_plaintext_name_not_exist(string plaintext_name);
            void check_ciphertext_name_not_exist(string ciphertext_name);
            Plaintext& get_plaintext(string plaintext_name);
            Ciphertext& get_ciphertext(string ciphertext_name);
    };
}

#endif