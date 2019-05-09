# distutils: language = c++
from libcpp.string cimport string
from libcpp.vector cimport vector
from libc.stdint cimport uint64_t
from cppwrapper cimport Wrapper

cdef class CythonWrapper:
    cdef Wrapper wrapper

    def __cinit__(self, string scheme, int security_level, int poly_modulus_degree, int coeff_modulus,
                  int plain_modulus):
        self.wrapper = Wrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)

    # context
    def context_chain_get_all_indexes(self):
        return self.wrapper.context_chain_get_all_indexes()

    def context_chain_get_parms_id_at_index(self, int index):
        return self.wrapper.context_chain_get_parms_id_at_index(index)

    def context_chain_print_coeff_modulus_primes_at_index(self, int index):
        return self.wrapper.context_chain_print_coeff_modulus_primes_at_index(index)

    def get_parms_id_for_encryption_parameters(self):
        return self.wrapper.get_parms_id_for_encryption_parameters()

    def get_parms_id_for_public_key(self):
        return self.wrapper.get_parms_id_for_public_key()

    def get_parms_id_for_secret_key(self):
        return self.wrapper.get_parms_id_for_secret_key()

    def get_parms_id_for_plaintext(self, string plaintext_name):
        return self.wrapper.get_parms_id_for_plaintext(plaintext_name)

    def get_parms_id_for_ciphertext(self, string ciphertext_name):
        return self.wrapper.get_parms_id_for_ciphertext(ciphertext_name)

    # pointer management
    def clear_all_stored_pointers(self):
        self.wrapper.clear_all_stored_pointers()

    def clear_plaintext(self, string plaintext_name):
        self.wrapper.clear_plaintext(plaintext_name)

    def clear_ciphertext(self, string ciphertext_name):
        self.wrapper.clear_ciphertext(ciphertext_name)

    # plaintext
    def plaintext_to_string(self, string plaintext_name):
        return self.wrapper.plaintext_to_string(plaintext_name)

    def plaintext_create(self, string expression, string plaintext_name):
        return self.wrapper.plaintext_create(expression, plaintext_name)

    # ciphertext
    def ciphertext_size(self, string ciphertext_name):
        return self.wrapper.ciphertext_size(ciphertext_name)

    # integer encoder
    def init_integer_encoder(self):
        self.wrapper.init_integer_encoder()

    def integer_encoder(self, int integer, string plaintext_name):
        return self.wrapper.integer_encoder(integer, plaintext_name)

    def integer_decoder(self, string plaintext_name):
        return self.wrapper.integer_decoder(plaintext_name)

    # batch encoder
    def init_batch_encoder(self):
        self.wrapper.init_batch_encoder()

    def batch_encoder(self, vector[uint64_t] pod_matrix, string plaintext_name):
        return self.wrapper.batch_encoder(pod_matrix, plaintext_name)

    def batch_decoder(self, string plaintext_name):
        return self.wrapper.batch_decoder(plaintext_name)

    # ckks encoder
    def init_ckks_encoder(self):
        self.wrapper.init_ckks_encoder()

    def ckks_encoder(self, vector[double] input, double scale, string plaintext_name):
        return self.wrapper.ckks_encoder(input, scale, plaintext_name)

    # encrypt & decrypt
    def decryptor_noise_budget(self, string ciphertext_name):
        return self.wrapper.decryptor_noise_budget(ciphertext_name)

    def encryptor_encrypt(self, string plaintext_name, string ciphertext_name):
        return self.wrapper.encryptor_encrypt(plaintext_name, ciphertext_name)

    def decryptor_decrypt(self, string ciphertext_name, string plaintext_name):
        return self.wrapper.decryptor_decrypt(ciphertext_name, plaintext_name)

    # evaluator
    def evaluator_relinearize_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_relinearize_inplace(ciphertext_name)

    def evaluator_negate_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_negate_inplace(ciphertext_name)

    def evaluator_add_inplace(self, string ciphertext_name1, string ciphertext_name2):
        self.wrapper.evaluator_add_inplace(ciphertext_name1, ciphertext_name2)

    def evaluator_multiply_inplace(self, string ciphertext_name1, string ciphertext_name2):
        self.wrapper.evaluator_multiply_inplace(ciphertext_name1, ciphertext_name2)

    def evaluator_square_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_square_inplace(ciphertext_name)

    def evaluator_add_plain_inplace(self, string ciphertext_name, string plaintext_name):
        self.wrapper.evaluator_add_plain_inplace(ciphertext_name, plaintext_name)

    def evaluator_rotate_rows_inplace(self, string ciphertext_name, int steps):
        self.wrapper.evaluator_rotate_rows_inplace(ciphertext_name, steps)

    def evaluator_rotate_columns_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_rotate_columns_inplace(ciphertext_name)

    def evaluator_mod_switch_to_next_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_mod_switch_to_next_inplace(ciphertext_name)

    # relinearization
    def relinearization_generate_keys(self, int decomposition_bit_count, int count):
        self.wrapper.relinearization_generate_keys(decomposition_bit_count, count)

    def relinearization_dbc_max(self):
        return self.wrapper.relinearization_dbc_max()

    def relinearization_dbc_min(self):
        return self.wrapper.relinearization_dbc_min()

    # batching
    def batching_is_enabled(self):
        return self.wrapper.batching_is_enabled()

    def batching_generate_galois_keys(self, int decomposition_bit_count):
        return self.wrapper.batching_generate_galois_keys(decomposition_bit_count)
