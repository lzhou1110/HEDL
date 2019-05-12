from libcpp.string cimport string
from libc.stdint cimport int64_t
from libc.stdint cimport uint64_t
from libcpp cimport bool
from libcpp.vector cimport vector


cdef extern from "cppwrapper.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppwrapper.h" namespace "wrapper":
    cdef cppclass Wrapper:

        # constructors
        Wrapper() except +
        Wrapper(string scheme) except +

        # set up
        void set_coeff_modulus(vector[uint64_t] coeff_modulus);
        void set_poly_modulus_degree(int poly_modulus_degree);
        void set_plain_modulus_for_bfv(int plain_modulus);
        void initiate_seal();

        # default
        vector[uint64_t] default_params_coeff_modulus_128(size_t poly_modulus_degeree);
        uint64_t default_params_small_mods_40bit(size_t index);
        int default_params_dbc_max();
        int default_params_dbc_min();

        # context
        vector[size_t] context_chain_get_all_indexes() except +
        vector[long unsigned int] context_chain_get_parms_id_at_index(size_t index) except +
        vector[long unsigned int] get_parms_id_for_encryption_parameters() except +
        vector[long unsigned int] get_parms_id_for_public_key() except +
        vector[long unsigned int] get_parms_id_for_secret_key() except +
        vector[long unsigned int] get_parms_id_for_plaintext(string plaintext_name) except +
        vector[long unsigned int] get_parms_id_for_ciphertext(string ciphertext_name) except +
        void context_chain_print_coeff_modulus_primes_at_index(size_t index) except +
        int get_total_coeff_modulus_bit_count(vector[long unsigned int] parms_id) except +
        size_t get_parms_index(vector[long unsigned int] parms_id) except +

        # pointers management
        void clear_all_stored_pointers() except +
        void clear_plaintext(string plaintext_name) except +
        void clear_ciphertext(string ciphertext_name) except +

        # plaintext
        string plaintext_to_string(string plaintext_name) except +
        string plaintext_create(string expression, string plaintext_name) except +

        # ciphertext
        int ciphertext_size(string ciphertext_name) except +

        # integer encoder
        void init_integer_encoder() except +
        string integer_encoder(int integer, string plaintext_name) except +
        int64_t integer_decoder(string plaintext_name) except +

        # batch encoder
        void init_batch_encoder() except +
        string batch_encoder(vector[uint64_t] pod_matrix, string plaintext_name) except +
        vector[uint64_t] batch_decoder(string plaintext_name) except +

        # ckks encoder
        void init_ckks_encoder() except +
        string ckks_encoder(vector[double] input, double scale, string plaintext_name) except +
        string ckks_encoder (
            vector[double] input,
            vector[long unsigned int] parms_id,
            double scale,
            string plaintext_name
        ) except +
        vector[double] ckks_decoder(string plaintext_name, int size) except +
        size_t ckks_slot_count() except +

        # encrypt & decrypt
        int decryptor_noise_budget(string ciphertext_name) except +
        string encryptor_encrypt(string plaintext_name, string ciphertext_name) except +
        string decryptor_decrypt(string ciphertext_name, string plaintext_name) except +

        # evaluator
        void evaluator_relinearize_inplace(string ciphertext_name) except +
        void evaluator_negate_inplace(string ciphertext_name) except +
        void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2) except +
        string evaluator_add(string ciphertext_name1, string ciphertext_name2, string ciphertext_output_name) except +
        void evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2) except +
        string evaluator_multiply_plain(string ciphertext_name, string plaintext_name, string ciphertext_output_name) except +
        void evaluator_multiply_plain_inplace(string ciphertext_name, string plaintext_name) except +
        string evaluator_square(string ciphertext_input_name, string ciphertext_output_name) except +
        void evaluator_square_inplace(string ciphertext_name) except +
        void evaluator_add_plain_inplace(string ciphertext_name, string plaintext_name) except +
        void evaluator_rotate_rows_inplace(string ciphertext_name, int steps) except +
        void evaluator_rotate_columns_inplace(string ciphertext_name) except +
        void evaluator_mod_switch_to_inplace_ciphertext(string ciphertext_name, vector[long unsigned int] parms_id) except +
        void evaluator_mod_switch_to_inplace_plaintext(string plaintext_name, vector[long unsigned int] parms_id) except +
        void evaluator_mod_switch_to_next_inplace(string ciphertext_name) except +
        void evaluator_rescale_to_next_inplace(string ciphertext_name) except +

        # relinearization
        void relinearization_generate_keys(int decomposition_bit_count, size_t count) except +

        # batching
        bool batching_is_enabled() except +
        void batching_generate_galois_keys(int decomposition_bit_count) except +

        # ckks
        double get_scale_for_plaintext(string plaintext_name) except +
        double get_scale_for_ciphertext(string ciphertext_name) except +
        void set_scale_for_plaintext(string plaintext_name, double scale) except +
        void set_scale_for_ciphertext(string ciphertext_name, double scale) except +