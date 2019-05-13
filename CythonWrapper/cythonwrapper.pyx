# distutils: language = c++
from libcpp.string cimport string
from libcpp.vector cimport vector
from libc.stdint cimport uint64_t
from cppwrapper cimport Wrapper
from cpython.version cimport PY_MAJOR_VERSION


def _bstr(object):
    if isinstance(object, str):
        return bytes(object, 'utf-8')
    if isinstance(object, bytes):
        return object
    raise Exception(f"Object of type {type(object)} could not be converted to bytes.")


cdef class CythonWrapper:
    cdef Wrapper wrapper

    def __cinit__(self, scheme):
        # - Brakerski/Fan-Vercauteren (BFV) scheme (https://eprint.iacr.org/2012/144), with FullRNS optimization
        #   (https://eprint.iacr.org/2016/510).
        # - Cheon-Kim-Kim-Song (CKKS) scheme (https://eprint.iacr.org/2016/421), with FullRNS optimization
        #   (https://eprint.iacr.org/2018/931).
        self.wrapper = Wrapper(_bstr(scheme))

    # set up
    def set_coeff_modulus(self, vector[uint64_t] coeff_modulus):
        # - coeff_modulus ([ciphertext] coefficient modulus) : size of the bit length of the product of primes
        #     - Bigger coefficient -> More noise bugget, Lower security
        #     - 128-bits and 192-bits already available, following Security Standard Draft
        #       http://HomomorphicEncryption.org
        #     - Defaults:
        #         DefaultParams::coeff_modulus_128(int)
        #         DefaultParams::coeff_modulus_192(int)
        #         DefaultParams::coeff_modulus_256(int)
        self.wrapper.set_coeff_modulus(coeff_modulus)

    def set_poly_modulus_degree(self, int poly_modulus_degree):
        # - poly_modulus_degree (degree of polynomial modulus)
        #     - Must be a power of 2, representing the degree of a power-of-2 cyclotomic polynomial.
        #     - Larger degree -> More secure, larger ciphertext sizes, slower operations.
        #     - Recommended degrees are 1024, 2048, 4096, 8192, 16384, 32768
        self.wrapper.set_poly_modulus_degree(poly_modulus_degree)

    def set_plain_modulus_for_bfv(self, int plain_modulus):
        # - plain_modulus (plaintext modulus)
        #     - any positive integer
        #     - affects:
        #         - size of the plaintext data type
        #         - noise budget in freshly encrypted cyphertext
        #         - consumption of noise budget in homomorphic (encrypted) multiplications
        self.wrapper.set_plain_modulus_for_bfv(plain_modulus)

    def initiate_seal(self):
        self.wrapper.initiate_seal()

    # default
    def default_coeff_modulus_128(self, size_t poly_modulus_degeree):
        return self.wrapper.default_params_coeff_modulus_128(poly_modulus_degeree)

    def default_small_mods_40bit(self, size_t index):
        return self.wrapper.default_params_small_mods_40bit(index)

    def default_dbc_max(self):
        return self.wrapper.default_params_dbc_max()

    def default_dbc_min(self):
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

    def get_parms_id_for_plaintext(self, plaintext_name):
        return self.wrapper.get_parms_id_for_plaintext(_bstr(plaintext_name))

    def get_parms_id_for_ciphertext(self, ciphertext_name):
        return self.wrapper.get_parms_id_for_ciphertext(_bstr(ciphertext_name))

    def context_chain_print_coeff_modulus_primes_at_index(self, int index):
        return self.wrapper.context_chain_print_coeff_modulus_primes_at_index(index)

    def get_total_coeff_modulus_bit_count(self, vector[long unsigned int] parms_id):
        return self.wrapper.get_total_coeff_modulus_bit_count(parms_id)

    def get_parms_index(self, vector[long unsigned int] parms_id):
        return self.wrapper.get_parms_index(parms_id)

    # pointer management
    def clear_all_stored_pointers(self):
        self.wrapper.clear_all_stored_pointers()

    def clear_plaintext(self, plaintext_name):
        self.wrapper.clear_plaintext(_bstr(plaintext_name))

    def clear_ciphertext(self, ciphertext_name):
        self.wrapper.clear_ciphertext(_bstr(ciphertext_name))

    # plaintext
    def plaintext_to_string(self, plaintext_name):
        return self.wrapper.plaintext_to_string(_bstr(plaintext_name))

    def plaintext_create(self, expression, plaintext_name):
        return self.wrapper.plaintext_create(_bstr(expression), _bstr(plaintext_name))

    # ciphertext
    def ciphertext_size(self, ciphertext_name):
        return self.wrapper.ciphertext_size(_bstr(ciphertext_name))

    # integer encoder
    def init_integer_encoder(self):
        self.wrapper.init_integer_encoder()

    def integer_encoder(self, int integer, plaintext_name):
        return self.wrapper.integer_encoder(integer, _bstr(plaintext_name))

    def integer_decoder(self, plaintext_name):
        return self.wrapper.integer_decoder(_bstr(plaintext_name))

    # batch encoder
    def init_batch_encoder(self):
        self.wrapper.init_batch_encoder()

    def batch_encoder(self, vector[uint64_t] pod_matrix, plaintext_name):
        return self.wrapper.batch_encoder(pod_matrix, _bstr(plaintext_name))

    def batch_decoder(self, plaintext_name):
        return self.wrapper.batch_decoder(_bstr(plaintext_name))

    # ckks encoder
    def init_ckks_encoder(self):
        self.wrapper.init_ckks_encoder()

    def ckks_encoder(self, vector[double] input, double scale, plaintext_name):
        return self.wrapper.ckks_encoder(input, scale, _bstr(plaintext_name))

    def ckks_encoder_with_parms(self, vector[double] input, vector[long unsigned int] parms_id, double scale,
                                plaintext_name):
        return self.wrapper.ckks_encoder(input, parms_id, scale, _bstr(plaintext_name))

    def ckks_decoder(self, plaintext_name, int size):
        return self.wrapper.ckks_decoder(_bstr(plaintext_name), size)

    def ckks_slot_count(self):
        return self.wrapper.ckks_slot_count()

    # encrypt & decrypt
    def decryptor_noise_budget(self, ciphertext_name):
        # Noise budget in a freshly made ciphertext = log2(coeff_modulus/plain_modulus) (bits)
        return self.wrapper.decryptor_noise_budget(_bstr(ciphertext_name))

    def encryptor_encrypt(self, plaintext_name, ciphertext_name):
        return self.wrapper.encryptor_encrypt(_bstr(plaintext_name), _bstr(ciphertext_name))

    def decryptor_decrypt(self, ciphertext_name, plaintext_name):
        return self.wrapper.decryptor_decrypt(_bstr(ciphertext_name), _bstr(plaintext_name))

    # evaluator
    def evaluator_relinearize_inplace(self, ciphertext_name):
        self.wrapper.evaluator_relinearize_inplace(_bstr(ciphertext_name))

    def evaluator_negate_inplace(self, ciphertext_name):
        self.wrapper.evaluator_negate_inplace(_bstr(ciphertext_name))

    def evaluator_add_inplace(self, ciphertext_name1, ciphertext_name2):
        self.wrapper.evaluator_add_inplace(_bstr(ciphertext_name1), _bstr(ciphertext_name2))

    def evaluator_multiply_inplace(self, ciphertext_name1, ciphertext_name2):
        self.wrapper.evaluator_multiply_inplace(_bstr(ciphertext_name1), _bstr(ciphertext_name2))

    def evaluator_multiply_plain(self, ciphertext_name, plaintext_name, ciphertext_output_name):
        return self.wrapper.evaluator_multiply_plain(_bstr(ciphertext_name), _bstr(plaintext_name), _bstr(ciphertext_output_name))

    def evaluator_multiply_plain_inplace(self, ciphertext_name, plaintext_name):
        self.wrapper.evaluator_multiply_plain_inplace(_bstr(ciphertext_name), _bstr(plaintext_name))

    def evaluator_square(self, ciphertext_input_name, ciphertext_output_name):
        return self.wrapper.evaluator_square(_bstr(ciphertext_input_name), _bstr(ciphertext_output_name))

    def evaluator_square_inplace(self, ciphertext_name):
        self.wrapper.evaluator_square_inplace(_bstr(ciphertext_name))

    def evaluator_add_plain_inplace(self, ciphertext_name, plaintext_name):
        self.wrapper.evaluator_add_plain_inplace(_bstr(ciphertext_name), _bstr(plaintext_name))

    def evaluator_add(self, ciphertext_name1, ciphertext_name2, ciphertext_output_name):
        return self.wrapper.evaluator_add(_bstr(ciphertext_name1), _bstr(ciphertext_name2), _bstr(ciphertext_output_name))

    def evaluator_rotate_rows_inplace(self, ciphertext_name, int steps):
        self.wrapper.evaluator_rotate_rows_inplace(_bstr(ciphertext_name), steps)

    def evaluator_rotate_columns_inplace(self, ciphertext_name):
        self.wrapper.evaluator_rotate_columns_inplace(_bstr(ciphertext_name))

    def evaluator_mod_switch_to_inplace_ciphertext(self, ciphertext_name, vector[long unsigned int] parms_id):
        self.wrapper.evaluator_mod_switch_to_inplace_ciphertext(_bstr(ciphertext_name), parms_id)

    def evaluator_mod_switch_to_inplace_plaintext(self, plaintext_name, vector[long unsigned int] parms_id):
        self.wrapper.evaluator_mod_switch_to_inplace_plaintext(_bstr(plaintext_name), parms_id)

    def evaluator_mod_switch_to_next_inplace(self, ciphertext_name):
        self.wrapper.evaluator_mod_switch_to_next_inplace(_bstr(ciphertext_name))

    def evaluator_rescale_to_next_inplace(self, ciphertext_name):
        self.wrapper.evaluator_rescale_to_next_inplace(_bstr(ciphertext_name))

    # relinearization
    def relinearization_generate_keys(self, int decomposition_bit_count, int count):
        self.wrapper.relinearization_generate_keys(decomposition_bit_count, count)

    # batching
    def batching_is_enabled(self):
        return self.wrapper.batching_is_enabled()

    def batching_generate_galois_keys(self, int decomposition_bit_count):
        return self.wrapper.batching_generate_galois_keys(decomposition_bit_count)

    # ckks
    def get_scale_for_plaintext(self, plaintext_name):
        return self.wrapper.get_scale_for_plaintext(_bstr(plaintext_name))

    def get_scale_for_ciphertext(self, ciphertext_name):
        return self.wrapper.get_scale_for_ciphertext(_bstr(ciphertext_name))

    def set_scale_for_plaintext(self, plaintext_name, double scale):
        self.wrapper.set_scale_for_plaintext(_bstr(plaintext_name), scale)

    def set_scale_for_ciphertext(self, ciphertext_name, double scale):
        self.wrapper.set_scale_for_ciphertext(_bstr(ciphertext_name), scale)
