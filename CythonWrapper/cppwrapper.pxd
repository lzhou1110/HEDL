from libcpp.string cimport string
from libc.stdint cimport int64_t
from libc.stdint cimport uint64_t
from libcpp cimport bool
from libcpp.vector cimport vector
from cython cimport ulong


cdef extern from "cppwrapper.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppwrapper.h" namespace "wrapper":
    cdef cppclass Wrapper:

        # constructors
        Wrapper() except +
        Wrapper(string scheme, int security_level, int poly_modulus_degree, int coeff_modulus, int plain_modulus) except +

        # context
        vector[size_t] context_chain_get_all_indexes() except +
        vector[long unsigned int] context_chain_get_parms_id_at_index(size_t index) except +
        void context_chain_print_coeff_modulus_primes_at_index(size_t index) except +
        vector[long unsigned int] get_parms_id_for_encryption_parameters()
        vector[long unsigned int] get_parms_id_for_public_key()
        vector[long unsigned int] get_parms_id_for_secret_key()
        vector[long unsigned int] get_parms_id_for_plaintext(string plaintext_name) except +
        vector[long unsigned int] get_parms_id_for_ciphertext(string ciphertext_name) except +

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

        # encrypt & decrypt
        int decryptor_noise_budget(string ciphertext_name) except +
        string encryptor_encrypt(string plaintext_name, string ciphertext_name) except +
        string decryptor_decrypt(string ciphertext_name, string plaintext_name) except +

        # evaluator
        void evaluator_relinearize_inplace(string ciphertext_name) except +
        void evaluator_negate_inplace(string ciphertext_name) except +
        void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2) except +
        void evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2) except +
        void evaluator_square_inplace(string ciphertext_name) except +
        void evaluator_add_plain_inplace(string ciphertext_name, string plaintext_name) except +
        void evaluator_rotate_rows_inplace(string ciphertext_name, int steps) except +
        void evaluator_rotate_columns_inplace(string ciphertext_name) except +
        void evaluator_mod_switch_to_next_inplace(string ciphertext_name) except +

        # relinearization
        void relinearization_generate_keys(int decomposition_bit_count, size_t count) except +
        int relinearization_dbc_max() except +
        int relinearization_dbc_min() except +

        # batching
        bool batching_is_enabled() except +
        void batching_generate_galois_keys(int decomposition_bit_count) except +