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
            // context
            string get_parms_id_for_encryption_parameters();
            string get_parms_id_for_public_key();
            string get_parms_id_for_secret_key();
            string get_parms_id_for_plaintext(string plaintext_name);
            string get_parms_id_for_ciphertext(string ciphertext_name);
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
            int64_t integer_decoder(string plaintext_name);
            // batch encoder
            void init_batch_encoder();
            string batch_encoder(vector<uint64_t> pod_matrix, string plaintext_name);
            vector<uint64_t> batch_decoder(string plaintext_name);
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
            void evaluator_add_plain_inplace(string ciphertext_name, string plaintext_name);
            void evaluator_rotate_rows_inplace(string ciphertext_name, int steps);
            void evaluator_rotate_columns_inplace(string ciphertext_name);
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
            // context
            EncryptionParameters*parms;
            shared_ptr<SEALContext> context;
            // encoders
            IntegerEncoder*integerEncoder;
            BatchEncoder*batchEncoder;
            // keys
            KeyGenerator*keygen;
            PublicKey public_key;
            SecretKey secret_key;
            RelinKeys relinearize_keys;
            GaloisKeys galois_keys;
            // encryptor, decryptor, evaluator, created using keys
            Encryptor*encryptor;
            Decryptor*decryptor;
            Evaluator*evaluator;
            // batching parameters for BFV only
            size_t batching_slot_count;
            size_t batching_row_count;

            /* Methods */
            void check_plaintext_name_exist(string plaintext_name);
            void check_ciphertext_name_exist(string ciphertext_name);
            void check_plaintext_name_not_exist(string plaintext_name);
            void check_ciphertext_name_not_exist(string ciphertext_name);
            Plaintext& get_plaintext(string plaintext_name);
            Ciphertext& get_ciphertext(string ciphertext_name);
            void print_matrix(vector<uint64_t> pod_matrix);
    };
}

#endif