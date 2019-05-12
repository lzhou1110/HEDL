# distutils: language = c++
from libcpp.string cimport string
from libcpp.vector cimport vector
from libc.stdint cimport uint64_t
from cppwrapper cimport Wrapper

cdef class CythonWrapper:
    cdef Wrapper wrapper

    def __cinit__(self, string scheme):
        self.wrapper = Wrapper(scheme)

    # set up
    def set_coeff_modulus(self, vector[uint64_t] coeff_modulus):
        self.wrapper.set_coeff_modulus(coeff_modulus)

    def set_poly_modulus_degree(self, int poly_modulus_degree):
        self.wrapper.set_poly_modulus_degree(poly_modulus_degree)

    def set_plain_modulus_for_bfv(self, int plain_modulus):
        self.wrapper.set_plain_modulus_for_bfv(plain_modulus)

    def initiate_seal(self):
        self.wrapper.initiate_seal()

    # default
    def default_params_coeff_modulus_128(self, size_t poly_modulus_degeree):
        return self.wrapper.default_params_coeff_modulus_128(poly_modulus_degeree)

    def default_params_small_mods_40bit(self, size_t index):
        return self.wrapper.default_params_small_mods_40bit(index)

    def default_params_dbc_max(self):
        return self.wrapper.default_params_dbc_max()

    def default_params_dbc_min(self):
        return self.wrapper.default_params_dbc_min()

    # context
    def context_chain_get_all_indexes(self):
        return self.wrapper.context_chain_get_all_indexes()

    def context_chain_get_parms_id_at_index(self, int index):
        return self.wrapper.context_chain_get_parms_id_at_index(index)

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

    def context_chain_print_coeff_modulus_primes_at_index(self, int index):
        return self.wrapper.context_chain_print_coeff_modulus_primes_at_index(index)

    def get_total_coeff_modulus_bit_count(self, vector[long unsigned int] parms_id):
        return self.wrapper.get_total_coeff_modulus_bit_count(parms_id)

    def get_parms_index(self, vector[long unsigned int] parms_id):
        return self.wrapper.get_parms_index(parms_id)

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

    def ckks_encoder_with_parms(self, vector[double] input, vector[long unsigned int] parms_id, double scale,
                                string plaintext_name):
        return self.wrapper.ckks_encoder(input, parms_id, scale, plaintext_name)

    def ckks_decoder(self, string plaintext_name, int size):
        return self.wrapper.ckks_decoder(plaintext_name, size)

    def ckks_slot_count(self):
        return self.wrapper.ckks_slot_count()

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

    def evaluator_multiply_plain(self, string ciphertext_name, string plaintext_name, string ciphertext_output_name):
        return self.wrapper.evaluator_multiply_plain(ciphertext_name, plaintext_name, ciphertext_output_name)

    def evaluator_multiply_plain_inplace(self, string ciphertext_name, string plaintext_name):
        self.wrapper.evaluator_multiply_plain_inplace(ciphertext_name, plaintext_name)

    def evaluator_square(self, string ciphertext_input_name, string ciphertext_output_name):
        return self.wrapper.evaluator_square(ciphertext_input_name, ciphertext_output_name)

    def evaluator_square_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_square_inplace(ciphertext_name)

    def evaluator_add_plain_inplace(self, string ciphertext_name, string plaintext_name):
        self.wrapper.evaluator_add_plain_inplace(ciphertext_name, plaintext_name)

    def evaluator_add(self, string ciphertext_name1, string ciphertext_name2, string ciphertext_output_name):
        return self.wrapper.evaluator_add(ciphertext_name1, ciphertext_name2, ciphertext_output_name)

    def evaluator_rotate_rows_inplace(self, string ciphertext_name, int steps):
        self.wrapper.evaluator_rotate_rows_inplace(ciphertext_name, steps)

    def evaluator_rotate_columns_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_rotate_columns_inplace(ciphertext_name)

    def evaluator_mod_switch_to_inplace_ciphertext(self, string ciphertext_name, vector[long unsigned int] parms_id):
        self.wrapper.evaluator_mod_switch_to_inplace_ciphertext(ciphertext_name, parms_id)

    def evaluator_mod_switch_to_inplace_plaintext(self, string plaintext_name, vector[long unsigned int] parms_id):
        self.wrapper.evaluator_mod_switch_to_inplace_plaintext(plaintext_name, parms_id)

    def evaluator_mod_switch_to_next_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_mod_switch_to_next_inplace(ciphertext_name)

    def evaluator_rescale_to_next_inplace(self, string ciphertext_name):
        self.wrapper.evaluator_rescale_to_next_inplace(ciphertext_name)

    # relinearization
    def relinearization_generate_keys(self, int decomposition_bit_count, int count):
        self.wrapper.relinearization_generate_keys(decomposition_bit_count, count)

    # batching
    def batching_is_enabled(self):
        return self.wrapper.batching_is_enabled()

    def batching_generate_galois_keys(self, int decomposition_bit_count):
        return self.wrapper.batching_generate_galois_keys(decomposition_bit_count)

    # ckks
    def get_scale_for_plaintext(self, string plaintext_name):
        return self.wrapper.get_scale_for_plaintext(plaintext_name)

    def get_scale_for_ciphertext(self, string ciphertext_name):
        return self.wrapper.get_scale_for_ciphertext(ciphertext_name)

    def set_scale_for_plaintext(self, string plaintext_name, double scale):
        self.wrapper.set_scale_for_plaintext(plaintext_name, scale)

    def set_scale_for_ciphertext(self, string ciphertext_name, double scale):
        self.wrapper.set_scale_for_ciphertext(ciphertext_name, scale)