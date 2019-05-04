from libcpp.string cimport string
from libc.stdint cimport int64_t
from libc.stdint cimport uintptr_t

cdef extern from "cppwrapper.cpp":
    pass

# Declare the class with cdef
cdef extern from "cppwrapper.h" namespace "wrapper":
    cdef cppclass Wrapper:

        # constructors
        Wrapper() except +
        Wrapper(string scheme, int security_level, int poly_modulus_degree, int coeff_modulus,
                int plain_modulus) except +

        # logging
        void print_seal_version()
        void print_parameters()
        void print_allocated_memory()

        # pointers management
        void clear_all_stored_pointers()
        void clear_plaintext(string plaintext_name)
        void clear_ciphertext(string ciphertext_name)

        # encoding
        string plaintext_to_string(string plaintext_name) except +

        # integer encoder
        void init_integer_encoder()
        string integer_encoder(int integer, string plaintext_name)
        int64_t integer_decoder(string plaintext_name)

        # encrypt & decrypt
        int decryptor_invariant_noise_budget(string ciphertext_name)
        string encryptor_encrypt(string plaintext_name, string ciphertext_name);
        string decryptor_decrypt(string ciphertext_name, string plaintext_name);

        # evaluator
        void evaluator_add_inplace(string ciphertext_name1, string ciphertext_name2)

