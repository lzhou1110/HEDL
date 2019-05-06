from libcpp.string cimport string
from libc.stdint cimport int64_t
from libc.stdint cimport uintptr_t
from libcpp cimport bool

cdef extern from "cppwrapper.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppwrapper.h" namespace "wrapper":
    cdef cppclass Wrapper:

        # constructors
        Wrapper() except +
        Wrapper(string scheme, int security_level, int poly_modulus_degree, int coeff_modulus, int plain_modulus) except +

        # logging
        void print_seal_version()
        void print_parameters()
        void print_allocated_memory()

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

        # encrypt & decrypt
        int decryptor_invariant_noise_budget(string ciphertext_name) except +
        string encryptor_encrypt(string plaintext_name, string ciphertext_name) except +
        string decryptor_decrypt(string ciphertext_name, string plaintext_name) except +

        # evaluator
        void evaluator_relinearize_inplace(string ciphertext_name) except +
        void evaluator_negate_inplace(string ciphertext_name) except +
        void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2) except +
        void evaluator_multiply_inplace(string ciphertext_name1, string ciphertext_name2) except +
        void evaluator_square_inplace(string ciphertext_name) except +

        # relinearization
        void relinearization_generate_keys(int decomposition_bit_count, size_t count) except +
        int relinearization_dbc_max() except +
        int relinearization_dbc_min() except +

        # batching
        bool batching_is_enabled() except +
        void batching_generate_galois_keys(int decomposition_bit_count) except +