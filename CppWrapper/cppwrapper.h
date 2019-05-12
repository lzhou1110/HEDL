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
            Wrapper(string scheme);
            ~Wrapper();
            /* Methods */
            // set up
            void set_coeff_modulus(vector<uint64_t> coeff_modulus);
            void set_poly_modulus_degree(int poly_modulus_degree);
            void set_plain_modulus_for_bfv(int plain_modulus);
            void initiate_seal();
            // default
            vector<uint64_t> default_params_coeff_modulus_128(size_t poly_modulus_degeree);
            uint64_t default_params_small_mods_40bit(size_t index);
            int default_params_dbc_max();
            int default_params_dbc_min();
            // context
            vector<size_t> context_chain_get_all_indexes();
            vector<long unsigned int> context_chain_get_parms_id_at_index(size_t index);
            vector<long unsigned int> get_parms_id_for_encryption_parameters();
            vector<long unsigned int> get_parms_id_for_public_key();
            vector<long unsigned int> get_parms_id_for_secret_key();
            vector<long unsigned int> get_parms_id_for_plaintext(string plaintext_name);
            vector<long unsigned int> get_parms_id_for_ciphertext(string ciphertext_name);
            void context_chain_print_coeff_modulus_primes_at_index(size_t index);
            int get_total_coeff_modulus_bit_count(vector<long unsigned int> parms_id);
            size_t get_parms_index(vector<long unsigned int> parms_id);
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
            // ckks encoder
            void init_ckks_encoder();
            string ckks_encoder(vector<double> input, double scale, string plaintext_name);
            string ckks_encoder (
                vector<double> input,
                vector<long unsigned int> parms_id,
                double scale, string plaintext_name
            );
            vector<double> ckks_decoder(string plaintext_name, int size);
            size_t ckks_slot_count();
            // encrypt & decrypt
            int decryptor_noise_budget(string ciphertext_name);
            string encryptor_encrypt(string plaintext_name, string ciphertext_name);
            string decryptor_decrypt(string ciphertext_name, string plaintext_name);
            // evaluator
            void evaluator_relinearize_inplace(string ciphertext_name);
            void evaluator_negate_inplace(string ciphertext_name);
            void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2);
            string evaluator_add(string ciphertext_name1, string ciphertext_name2, string ciphertext_output_name);
            void evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2);
            string evaluator_multiply_plain(string ciphertext_name, string plaintext_name, string ciphertext_output_name);
            void evaluator_multiply_plain_inplace(string ciphertext_name, string plaintext_name);
            string evaluator_square(string ciphertext_input_name, string ciphertext_output_name);
            void evaluator_square_inplace(string ciphertext_name);
            void evaluator_add_plain_inplace(string ciphertext_name, string plaintext_name);
            void evaluator_rotate_rows_inplace(string ciphertext_name, int steps);
            void evaluator_rotate_columns_inplace(string ciphertext_name);
            void evaluator_mod_switch_to_inplace_ciphertext(string ciphertext_name, vector<long unsigned int> parms_id);
            void evaluator_mod_switch_to_inplace_plaintext(string plaintext_name, vector<long unsigned int> parms_id);
            void evaluator_mod_switch_to_next_inplace(string ciphertext_name);
            void evaluator_rescale_to_next_inplace(string ciphertext_name);
            // relinearization
            void relinearization_generate_keys(int decomposition_bit_count, size_t count);
            // batching
            bool batching_is_enabled();
            void batching_generate_galois_keys(int decomposition_bit_count);
            // ckks
            double get_scale_for_plaintext(string plaintext_name);
            double get_scale_for_ciphertext(string ciphertext_name);
            void set_scale_for_plaintext(string plaintext_name, double scale);
            void set_scale_for_ciphertext(string ciphertext_name, double scale);


        private:
            /* Members */
            string scheme;
            map<string, Plaintext> plaintext_map;
            map<string, Ciphertext> ciphertext_map;
            // context
            EncryptionParameters*parms;
            shared_ptr<SEALContext> context;
            // encoders
            IntegerEncoder*integerEncoder;
            BatchEncoder*batchEncoder;
            CKKSEncoder*ckksEncoder;
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
            void print_info();
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