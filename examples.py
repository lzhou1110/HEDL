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


def bfv_example_3():
    print("===========Example: BFV Basics III===========")
    np.set_printoptions(precision=2)
    scheme = bstr("BFV")
    security_level = 128
    poly_modulus_degree = 4096
    coeff_modulus = 4096
    plain_modulus = 40961
    # Note here, plain_modulues congruent to 1 mod 2*ploy_modulus_degree, thus batching is enabled
    wrapper = CythonWrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)
    wrapper.print_seal_version()
    wrapper.print_allocated_memory()
    wrapper.print_parameters()
    print(f"Is batching enabled? {wrapper.batching_is_enabled()}")
    wrapper.batching_generate_galois_keys(30)
    wrapper.relinearization_generate_keys(30, 1)
    wrapper.init_batch_encoder()
    python_pod_matrix1 = np.zeros((2, 2048), dtype=np.uint64)
    python_pod_matrix1[0, 1] = 1
    python_pod_matrix1[0, 2] = 2
    python_pod_matrix1[0, 3] = 3
    python_pod_matrix1[1, 0] = 4
    python_pod_matrix1[1, 1] = 5
    python_pod_matrix1[1, 2] = 6
    python_pod_matrix1[1, 3] = 7
    print(f"First input matrix:\n{python_pod_matrix1}")
    python_pod_matrix2 = np.ones((2, 2048), dtype=np.uint64)
    for i in range(2):
        for j in range(2048):
            if j % 2 == 1:
                python_pod_matrix2[i, j] = 2
    print(f"Second input matrix:\n{python_pod_matrix2}")
    # Experiment 1, batching a vector
    plaintext1 = wrapper.batch_encoder(python_pod_matrix1.flatten(), bstr('plaintext1'))
    ciphertext1 = wrapper.encryptor_encrypt(plaintext1, bstr('ciphertext1'))
    plaintext2 = wrapper.batch_encoder(python_pod_matrix2.flatten(), bstr('plaintext2'))
    wrapper.evaluator_add_plain_inplace(ciphertext1, plaintext2)
    wrapper.evaluator_square_inplace(ciphertext1)
    wrapper.evaluator_relinearize_inplace(ciphertext1)
    print(f"Noise budget in result: {wrapper.decryptor_invariant_noise_budget(ciphertext1)} bits")
    result_plaintext = wrapper.decryptor_decrypt(ciphertext1, bstr('result_plaintext'))
    result = np.array(wrapper.batch_decoder(result_plaintext)).reshape(2, 2048)
    print(f"Result matrix:\n{result}")
    wrapper.clear_all_stored_pointers()
    # Experiment 2, matrix rotation
    plaintext1 = wrapper.batch_encoder(python_pod_matrix1.flatten(), bstr('plaintext1'))
    ciphertext1 = wrapper.encryptor_encrypt(plaintext1, bstr('ciphertext1'))
    print(f"Noise budget in fresh encryption: {wrapper.decryptor_invariant_noise_budget(ciphertext1)}")

    wrapper.evaluator_rotate_rows_inplace(ciphertext1, 3)
    plaintext_row_rotate_3 = wrapper.decryptor_decrypt(ciphertext1, bstr("plaintext_row_rotate_3"))
    matrix_row_rotate_3 = np.array(wrapper.batch_decoder(plaintext_row_rotate_3)).reshape(2, 2048)
    print(f"Rotated matrix 3 steps to left:\n{matrix_row_rotate_3}")
    print(f"Noise budget after rotation: {wrapper.decryptor_invariant_noise_budget(ciphertext1)} bits")

    wrapper.evaluator_rotate_columns_inplace(ciphertext1)
    plaintext_col_rotate = wrapper.decryptor_decrypt(ciphertext1, bstr("plaintext_col_rotate"))
    matrix_col_rotate = np.array(wrapper.batch_decoder(plaintext_col_rotate)).reshape(2, 2048)
    print(f"Rotated matrix col:\n{matrix_col_rotate}")
    print(f"Noise budget after rotation: {wrapper.decryptor_invariant_noise_budget(ciphertext1)} bits")

    wrapper.evaluator_rotate_rows_inplace(ciphertext1, -4)
    plaintext_row_rotate_n4 = wrapper.decryptor_decrypt(ciphertext1, bstr("plaintext_row_rotate_n4"))
    matrix_row_rotate_n4 = np.array(wrapper.batch_decoder(plaintext_row_rotate_n4)).reshape(2, 2048)
    print(f"Rotated matrix 4 steps to right:\n{matrix_row_rotate_n4}")
    print(f"Noise budget after rotation: {wrapper.decryptor_invariant_noise_budget(ciphertext1)} bits")
    wrapper.clear_all_stored_pointers()


def bfv_example_4():
    print("===========Example: BFV Basics IV===========")
    # Introducing parms_id
    scheme = bstr("BFV")
    security_level = 128
    poly_modulus_degree = 8192
    coeff_modulus = 8192
    plain_modulus = np.power(2, 20)
    wrapper = CythonWrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)
    print(f"parms_id: {wrapper.get_parms_id_for_encryption_parameters()}")
    print("Changing plain_modulus ...")
    plain_modulus = np.power(2, 20) + 1
    wrapper = CythonWrapper(scheme, security_level, poly_modulus_degree, coeff_modulus, plain_modulus)
    print(f"parms_id: {wrapper.get_parms_id_for_encryption_parameters()}")
    wrapper.print_parameters()
    print(f"parms_id of public key: {wrapper.get_parms_id_for_public_key()}")
    print(f"parms_id of secret key: {wrapper.get_parms_id_for_secret_key()}")
    plaintext = wrapper.plaintext_create(bstr("1x^3 + 2x^2 + 3x^1 + 4"), bstr("plaintext"))
    ciphertext = wrapper.encryptor_encrypt(plaintext, bstr("ciphertext"))
    print(f"parms_id of plaintext: {wrapper.get_parms_id_for_plaintext(plaintext)} (not set for BFV)")
    print(f"parms_id of ciphertext: {wrapper.get_parms_id_for_ciphertext(ciphertext)}")
    wrapper.print_modulus_switching_chain()
    print("Beginning of chain")
    print(f"parms_id of ciphertext: {wrapper.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {wrapper.decryptor_invariant_noise_budget(ciphertext)}")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {wrapper.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {wrapper.decryptor_invariant_noise_budget(ciphertext)}")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {wrapper.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {wrapper.decryptor_invariant_noise_budget(ciphertext)}")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {wrapper.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {wrapper.decryptor_invariant_noise_budget(ciphertext)}")
    decrypted_plaintext = wrapper.decryptor_decrypt(ciphertext, bstr("decrypted_plaintext"))
    print(f"Decryption: {wrapper.plaintext_to_string(decrypted_plaintext)}")
    wrapper.clear_all_stored_pointers()
    # A demo
    wrapper.relinearization_generate_keys(wrapper.relinearization_dbc_max(), 1);
    plaintext = wrapper.plaintext_create(bstr("1x^3 + 2x^2 + 3x^1 + 4"), bstr("plaintext"))
    ciphertext = wrapper.encryptor_encrypt(plaintext, bstr("ciphertext"))
    print(f"Noise budget before squaring: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_square_inplace(ciphertext)
    wrapper.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_square_inplace(ciphertext)
    wrapper.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_square_inplace(ciphertext)
    wrapper.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    wrapper.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {wrapper.decryptor_invariant_noise_budget(ciphertext)} bits")
    decrypted_plaintext = wrapper.decryptor_decrypt(ciphertext, bstr("decrypted_plaintext"))
    print(f"Decryption of eighth power: {wrapper.plaintext_to_string(decrypted_plaintext)}")

