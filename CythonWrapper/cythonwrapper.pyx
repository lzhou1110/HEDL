# distutils: language = c++
from libcpp.string cimport string
from libc.stdint cimport uintptr_t
from cppwrapper cimport Wrapper


cdef class CythonWrapper:
    cdef Wrapper wrapper

    def __cinit__(self, string scheme, int security_level, int poly_modulus_degree, int coeff_modulus,
                  int plain_modulus):
        self.wrapper = Wrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)

    # logging
    def print_seal_version(self):
        self.wrapper.print_seal_version()

    def print_parameters(self):
        self.wrapper.print_parameters()

    def print_allocated_memory(self):
        self.wrapper.print_allocated_memory()

    # memory management
    def clear_all_stored_pointers(self):
        self.wrapper.clear_all_stored_pointers()

    def clear_plaintext(self, string plaintext_name):
        self.wrapper.clear_plaintext(plaintext_name)

    def clear_ciphertext(self, string ciphertext_name):
        self.wrapper.clear_ciphertext(ciphertext_name)

    # encoding
    def plaintext_to_string(self, string plaintext_name):
        return self.wrapper.plaintext_to_string(plaintext_name)

    # integer encoder
    def init_integer_encoder(self):
        self.wrapper.init_integer_encoder()

    def integer_encoder(self, int integer, string plaintext_name):
        return self.wrapper.integer_encoder(integer, plaintext_name)

    def integer_decoder(self, string plaintext_name):
        return self.wrapper.integer_decoder(plaintext_name)

    # encrypt & decrypt
    def decryptor_invariant_noise_budget(self, string ciphertext_name):
        return self.wrapper.decryptor_invariant_noise_budget(ciphertext_name)

    def encryptor_encrypt(self, string plaintext_name, string ciphertext_name):
        return self.wrapper.encryptor_encrypt(plaintext_name, ciphertext_name)

    def decryptor_decrypt(self, string ciphertext_name, string plaintext_name):
        return self.wrapper.decryptor_decrypt(ciphertext_name, plaintext_name)

    # evaluator
    def evaluator_add_inplace(self, string ciphertext_name1, string ciphertext_name2):
        self.wrapper.evaluator_add_inplace(ciphertext_name1, ciphertext_name2)