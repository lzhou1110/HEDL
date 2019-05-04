from CythonWrapper.cythonwrapper import CythonWrapper
import numpy as np

from utils import bstr


def bfv_example_1():
    print("===========Example: BFV Basics I===========")
    scheme = bstr("BFV")
    security_level = 128
    poly_modulus_degree = 2048
    coeff_modulus = 2048
    plain_modulus = np.power(2, 8)
    wrapper = CythonWrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)
    wrapper.print_seal_version()
    wrapper.print_allocated_memory()
    wrapper.print_parameters()

    # Using integer encoder
    wrapper.init_integer_encoder()

    value1 = 5
    value2 = -7
    plain1 = wrapper.integer_encoder(value1, bstr('plain1'))
    plain2 = wrapper.integer_encoder(value2, bstr('plain2'))
    print("Encoded {} as polynomial {}".format(value1, wrapper.plaintext_to_string(plain1)))
    print("Encoded {} as polynomial {}".format(value2, wrapper.plaintext_to_string(plain2)))

    cipher1 = wrapper.encryptor_encrypt(plain1, bstr('cipher1'))
    cipher2 = wrapper.encryptor_encrypt(plain2, bstr('cipher2'))
    print("Noise budget cipher1: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher1)))
    print("Noise budget cipher2: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher2)))

    wrapper.evaluator_negate_inplace(cipher1)
    print("Noise budget -cipher1: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher1)))

    wrapper.evaluator_add_inplace(cipher1, cipher2)
    print("Noise budge -cipher1 + cipher2: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher1)))

    wrapper.evaluator_multiply_inplace(cipher1, cipher2)
    print("Noise budge (-cipher1 + cipher2) * cipher2: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher1)))

    plain_result = wrapper.decryptor_decrypt(cipher1, bstr('plain_result'))
    print("Plaintext polynomial: {}".format(wrapper.plaintext_to_string(plain_result)))
    print("Decoded integer: {}".format(wrapper.integer_decoder(plain_result)))
    wrapper.clear_all_stored_pointers()


def bfv_example_2():
    print("===========Example: BFV Basics II===========")
    scheme = bstr("BFV")
    security_level = 128
    poly_modulus_degree = 8192
    coeff_modulus = 8192
    plain_modulus = np.power(2, 10)
    wrapper = CythonWrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)
    wrapper.print_seal_version()
    wrapper.print_allocated_memory()
    wrapper.print_parameters()

    print("\nExperiment 1: without relinearization \n")
    plain = wrapper.plaintext_create(bstr("1x^2 + 2x^1 + 3"), bstr('plain'))
    print('Encrypting plaintext: {}'.format(wrapper.plaintext_to_string(plain)))
    cipher = wrapper.encryptor_encrypt(plain, bstr('cipher'))
    print('Size of a fresh encryption: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget in fresh encryption: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after second squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after second squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    power4_result = wrapper.decryptor_decrypt(cipher, bstr('power4_result'))
    print("Fourth power result: {}".format(wrapper.plaintext_to_string(power4_result)))
    wrapper.clear_all_stored_pointers()

    print("\nExperiment 2, with relinearization of 16 dbc \n")
    decomposition_bit_count = 16
    relinearization_key_size = 1
    wrapper.relinearization_generate_keys(decomposition_bit_count, relinearization_key_size)
    plain = wrapper.plaintext_create(bstr("1x^2 + 2x^1 + 3"), bstr('plain'))
    print('Encrypting plaintext: {}'.format(wrapper.plaintext_to_string(plain)))
    cipher = wrapper.encryptor_encrypt(plain, bstr('cipher'))
    print('Size of a fresh encryption: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget in fresh encryption: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_relinearize_inplace(cipher)
    print('Size after relinearization: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after relinearization: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after second squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after second squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_relinearize_inplace(cipher)
    print('Size after relinearization: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after relinearization: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    power4_result = wrapper.decryptor_decrypt(cipher, bstr('power4_result'))
    print("Fourth power result: {}".format(wrapper.plaintext_to_string(power4_result)))
    wrapper.clear_all_stored_pointers()

    print("\nExperiment 3, with relinearization of max dbc \n")
    decomposition_bit_count = wrapper.relinearization_dbc_max()
    relinearization_key_size = 1
    wrapper.relinearization_generate_keys(decomposition_bit_count, relinearization_key_size)
    plain = wrapper.plaintext_create(bstr("1x^2 + 2x^1 + 3"), bstr('plain'))
    print('Encrypting plaintext: {}'.format(wrapper.plaintext_to_string(plain)))
    cipher = wrapper.encryptor_encrypt(plain, bstr('cipher'))
    print('Size of a fresh encryption: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget in fresh encryption: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_relinearize_inplace(cipher)
    print('Size after relinearization: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after relinearization: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_square_inplace(cipher)
    print('Size after second squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after second squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_relinearize_inplace(cipher)
    print('Size after relinearization: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after relinearization: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    power4_result = wrapper.decryptor_decrypt(cipher, bstr('power4_result'))
    print("Fourth power result: {}".format(wrapper.plaintext_to_string(power4_result)))

    wrapper.evaluator_square_inplace(cipher)
    print('Size after third squaring: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after third squaring: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    wrapper.evaluator_relinearize_inplace(cipher)
    print('Size after relinearization: {}'.format(wrapper.ciphertext_size(cipher)))
    print('Noise budget after relinearization: {} bits'.format(wrapper.decryptor_invariant_noise_budget(cipher)))
    power8_result = wrapper.decryptor_decrypt(cipher, bstr('power8_result'))
    print("Eighth power result: {}".format(wrapper.plaintext_to_string(power8_result)))
    wrapper.clear_all_stored_pointers()

