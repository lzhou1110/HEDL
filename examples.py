from CythonWrapper.cythonwrapper import CythonWrapper
from CythonWrapper.cythonperformance import CythonPerformance
import numpy as np

def bfv_example_1():
    print("===========Example: BFV Basics I===========")
    seal = CythonWrapper("BFV")
    seal.set_poly_modulus_degree(2048)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(2048))
    seal.set_plain_modulus_for_bfv(np.power(2, 8))
    seal.initiate_seal()

    # Using integer encoder
    seal.init_integer_encoder()
    plain1 = seal.integer_encoder(5, 'plain1')
    plain2 = seal.integer_encoder(-7, 'plain2')
    print(f"Encoded 5 as polynomial: {seal.plaintext_to_string(plain1)}")
    print(f"Encoded -7 as polynomial: {seal.plaintext_to_string(plain2)}")

    cipher1 = seal.encryptor_encrypt(plain1, 'cipher1')
    cipher2 = seal.encryptor_encrypt(plain2, 'cipher2')
    print(f"Noise budget cipher1: {seal.decryptor_noise_budget(cipher1)} bits")
    print(f"Noise budget cipher2: {seal.decryptor_noise_budget(cipher2)} bits")
    seal.evaluator_negate_inplace(cipher1)
    print(f"Noise budget -cipher1: {seal.decryptor_noise_budget(cipher1)} bits")
    seal.evaluator_add_inplace(cipher1, cipher2)
    print(f"Noise budget -cipher1+cipher2: {seal.decryptor_noise_budget(cipher1)} bits")
    seal.evaluator_multiply_inplace(cipher1, cipher2)
    print(f"Noise budget (-cipher1+cipher2)*cipher2: {seal.decryptor_noise_budget(cipher1)} bits")
    plain_result = seal.decryptor_decrypt(cipher1, 'plain_result')
    print(f"Plaintext polynomial: {seal.plaintext_to_string(plain_result)}")
    print(f"Decoded integer: {seal.integer_decoder(plain_result)}")

    seal.clear_all_stored_pointers()


def bfv_example_2():
    print("===========Example: BFV Basics II===========")
    seal = CythonWrapper("BFV")
    seal.set_poly_modulus_degree(8192)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(8192))
    seal.set_plain_modulus_for_bfv(np.power(2, 10))
    seal.initiate_seal()

    print("\nExperiment 1: without relinearization \n")
    plain = seal.plaintext_create("1x^2 + 2x^1 + 3", 'plain')
    print(f'Encrypting plaintext: {seal.plaintext_to_string(plain)}')
    cipher = seal.encryptor_encrypt(plain, 'cipher')
    print(f'Size of a fresh encryption: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget in fresh encryption: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print('Size after squaring: {}'.format(seal.ciphertext_size(cipher)))
    print(f'Noise budget after squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print(f'Size after second squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after second squaring: {seal.decryptor_noise_budget(cipher)} bits')
    power4_result = seal.decryptor_decrypt(cipher, 'power4_result')
    print(f"Fourth power result: {seal.plaintext_to_string(power4_result)}")
    seal.clear_all_stored_pointers()

    print("\nExperiment 2, with relinearization of 16 dbc \n")
    decomposition_bit_count = 16
    relinearization_key_size = 1
    seal.relinearization_generate_keys(decomposition_bit_count, relinearization_key_size)
    plain = seal.plaintext_create("1x^2 + 2x^1 + 3", 'plain')
    print(f'Encrypting plaintext: {seal.plaintext_to_string(plain)}')
    cipher = seal.encryptor_encrypt(plain, 'cipher')
    print(f'Size of a fresh encryption: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget in fresh encryption: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print(f'Size after squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_relinearize_inplace(cipher)
    print(f'Size after relinearization: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after relinearization: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print(f'Size after second squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after second squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_relinearize_inplace(cipher)
    print(f'Size after relinearization: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after relinearization: {seal.decryptor_noise_budget(cipher)} bits')
    power4_result = seal.decryptor_decrypt(cipher, 'power4_result')
    print(f"Fourth power result: {seal.plaintext_to_string(power4_result)}")
    seal.clear_all_stored_pointers()

    print("\nExperiment 3, with relinearization of max dbc \n")
    decomposition_bit_count = seal.default_dbc_max()
    relinearization_key_size = 1
    seal.relinearization_generate_keys(decomposition_bit_count, relinearization_key_size)
    plain = seal.plaintext_create("1x^2 + 2x^1 + 3", 'plain')
    print(f'Encrypting plaintext: {seal.plaintext_to_string(plain)}')
    cipher = seal.encryptor_encrypt(plain, 'cipher')
    print(f'Size of a fresh encryption: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget in fresh encryption: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print(f'Size after squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_relinearize_inplace(cipher)
    print(f'Size after relinearization: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after relinearization: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_square_inplace(cipher)
    print(f'Size after second squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after second squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_relinearize_inplace(cipher)
    print(f'Size after relinearization: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after relinearization: {seal.decryptor_noise_budget(cipher)} bits')
    power4_result = seal.decryptor_decrypt(cipher, 'power4_result')
    print(f"Fourth power result: {seal.plaintext_to_string(power4_result)}")
    seal.evaluator_square_inplace(cipher)
    print(f'Size after third squaring: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after third squaring: {seal.decryptor_noise_budget(cipher)} bits')
    seal.evaluator_relinearize_inplace(cipher)
    print(f'Size after relinearization: {seal.ciphertext_size(cipher)}')
    print(f'Noise budget after relinearization: {seal.decryptor_noise_budget(cipher)} bits')
    power8_result = seal.decryptor_decrypt(cipher, 'power8_result')
    print(f"Eighth power result: {seal.plaintext_to_string(power8_result)}")
    seal.clear_all_stored_pointers()


def bfv_example_3():
    np.set_printoptions(precision=3)
    print("===========Example: BFV Basics III===========")
    seal = CythonWrapper("BFV")
    seal.set_poly_modulus_degree(4096)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(4096))
    # Note here, plain_modulues congruent to 1 mod 2*ploy_modulus_degree, thus batching is enabled
    seal.set_plain_modulus_for_bfv(40961)
    seal.initiate_seal()

    print(f"Is batching enabled? {seal.batching_is_enabled()}")
    seal.batching_generate_galois_keys(30)
    seal.relinearization_generate_keys(30, 1)
    seal.init_batch_encoder()
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
    plaintext1 = seal.batch_encoder(python_pod_matrix1.flatten(), 'plaintext1')
    ciphertext1 = seal.encryptor_encrypt(plaintext1, 'ciphertext1')
    plaintext2 = seal.batch_encoder(python_pod_matrix2.flatten(), 'plaintext2')
    seal.evaluator_add_plain_inplace(ciphertext1, plaintext2)
    seal.evaluator_square_inplace(ciphertext1)
    seal.evaluator_relinearize_inplace(ciphertext1)
    print(f"Noise budget in result: {seal.decryptor_noise_budget(ciphertext1)} bits")
    result_plaintext = seal.decryptor_decrypt(ciphertext1, 'result_plaintext')
    result = np.array(seal.batch_decoder(result_plaintext)).reshape(2, 2048)
    print(f"Result matrix:\n{result}")
    seal.clear_all_stored_pointers()
    # Experiment 2, matrix rotation
    plaintext1 = seal.batch_encoder(python_pod_matrix1.flatten(), 'plaintext1')
    ciphertext1 = seal.encryptor_encrypt(plaintext1, 'ciphertext1')
    print(f"Noise budget in fresh encryption: {seal.decryptor_noise_budget(ciphertext1)}")

    seal.evaluator_rotate_rows_inplace(ciphertext1, 3)
    plaintext_row_rotate_3 = seal.decryptor_decrypt(ciphertext1, "plaintext_row_rotate_3")
    matrix_row_rotate_3 = np.array(seal.batch_decoder(plaintext_row_rotate_3)).reshape(2, 2048)
    print(f"Rotated matrix 3 steps to left:\n{matrix_row_rotate_3}")
    print(f"Noise budget after rotation: {seal.decryptor_noise_budget(ciphertext1)} bits")

    seal.evaluator_rotate_columns_inplace(ciphertext1)
    plaintext_col_rotate = seal.decryptor_decrypt(ciphertext1, "plaintext_col_rotate")
    matrix_col_rotate = np.array(seal.batch_decoder(plaintext_col_rotate)).reshape(2, 2048)
    print(f"Rotated matrix col:\n{matrix_col_rotate}")
    print(f"Noise budget after rotation: {seal.decryptor_noise_budget(ciphertext1)} bits")

    seal.evaluator_rotate_rows_inplace(ciphertext1, -4)
    plaintext_row_rotate_n4 = seal.decryptor_decrypt(ciphertext1, "plaintext_row_rotate_n4")
    matrix_row_rotate_n4 = np.array(seal.batch_decoder(plaintext_row_rotate_n4)).reshape(2, 2048)
    print(f"Rotated matrix 4 steps to right:\n{matrix_row_rotate_n4}")
    print(f"Noise budget after rotation: {seal.decryptor_noise_budget(ciphertext1)} bits")
    seal.clear_all_stored_pointers()


def bfv_example_4():
    print("===========Example: BFV Basics IV===========")
    seal = CythonWrapper("BFV")
    seal.set_poly_modulus_degree(8192)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(8192))
    # Note here, plain_modulues congruent to 1 mod 2*ploy_modulus_degree, thus batching is enabled
    seal.set_plain_modulus_for_bfv(np.power(2, 20))
    seal.initiate_seal()

    # Introducing parms_id
    print(f"parms_id: {seal.get_parms_id_for_encryption_parameters()}")
    print("Changing plain_modulus ...")
    plain_modulus = np.power(2, 20) + 1
    seal.set_plain_modulus_for_bfv(np.power(2, 20) + 1)
    seal.initiate_seal()
    print(f"parms_id: {seal.get_parms_id_for_encryption_parameters()}")
    print(f"parms_id of public key: {seal.get_parms_id_for_public_key()}")
    print(f"parms_id of secret key: {seal.get_parms_id_for_secret_key()}")
    plaintext = seal.plaintext_create("1x^3 + 2x^2 + 3x^1 + 4", "plaintext")
    ciphertext = seal.encryptor_encrypt(plaintext, "ciphertext")
    print(f"parms_id of plaintext: {seal.get_parms_id_for_plaintext(plaintext)} (not set for BFV)")
    print(f"parms_id of ciphertext: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    # seal.print_modulus_switching_chain()

    for chain_index in seal.context_chain_get_all_indexes():
        print(f"Index: {chain_index}")
        print(f"Parm_id: {seal.context_chain_get_parms_id_at_index(chain_index)}")
        seal.context_chain_print_coeff_modulus_primes_at_index(chain_index)
    print("Beginning of chain")
    print(f"parms_id of ciphertext: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {seal.decryptor_noise_budget(ciphertext)}")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {seal.decryptor_noise_budget(ciphertext)}")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {seal.decryptor_noise_budget(ciphertext)}")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms_id of ciphertext: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Noise budget at this level: {seal.decryptor_noise_budget(ciphertext)}")
    decrypted_plaintext = seal.decryptor_decrypt(ciphertext, "decrypted_plaintext")
    print(f"Decryption: {seal.plaintext_to_string(decrypted_plaintext)}")
    seal.clear_all_stored_pointers()
    # A demo
    seal.relinearization_generate_keys(seal.default_dbc_max(), 1);
    plaintext = seal.plaintext_create("1x^3 + 2x^2 + 3x^1 + 4", "plaintext")
    ciphertext = seal.encryptor_encrypt(plaintext, "ciphertext")
    print(f"Noise budget before squaring: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    print(f"Noise budget after squaring: {seal.decryptor_noise_budget(ciphertext)} bits")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"Noise budget after mod switching: {seal.decryptor_noise_budget(ciphertext)} bits")
    decrypted_plaintext = seal.decryptor_decrypt(ciphertext, "decrypted_plaintext")
    print(f"Decryption of eighth power: {seal.plaintext_to_string(decrypted_plaintext)}")
    seal.clear_all_stored_pointers()


def ckks_example_1():
    np.set_printoptions(precision=3)
    print("===========Example: CKKS Basics I===========")
    seal = CythonWrapper("CKKS")
    seal.set_poly_modulus_degree(8192)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(8192))
    # Note here, plain_modulues congruent to 1 mod 2*ploy_modulus_degree, thus batching is enabled
    seal.initiate_seal()

    seal.relinearization_generate_keys(seal.default_dbc_max(), 1)
    seal.init_ckks_encoder()
    input = np.array([0.0, 1.1, 2.2, 3.3], dtype=np.double)
    scale = np.power(2.0, 60).astype(np.double)
    print(scale)
    print(f"Input vector: {input}")
    plaintext = seal.ckks_encoder(input, scale, 'plaintext')
    ciphertext = seal.encryptor_encrypt(plaintext, 'ciphertext')
    print(f"param_id of plaintext {seal.get_parms_id_for_plaintext(plaintext)}")
    print(f"param_id of ciphertext {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Scale in plaintext: {seal.get_scale_for_plaintext(plaintext)}")
    print(f"Scale in ciphertext: {seal.get_scale_for_ciphertext(ciphertext)}")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    decrypted_plaintext = seal.decryptor_decrypt(ciphertext, 'decrypted_plaintext')
    print(f"Squared input: {seal.ckks_decoder(decrypted_plaintext, 4)}")
    print(f"Scale in the square {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")
    print(f"Current parms id: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    seal.evaluator_mod_switch_to_next_inplace(ciphertext)
    print(f"parms id after mod switching: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    decrypted_plaintext_after_switching = seal.decryptor_decrypt(ciphertext,
                                                                 'decrypted_plaintext_after_switching')
    print(f"Squared input: {seal.ckks_decoder(decrypted_plaintext_after_switching, 4)}")
    input2 = np.array([20.2, 30.3, 40.4, 50.5], dtype=np.double)
    plaintext2 = seal.ckks_encoder_with_parms(
        input2,
        seal.get_parms_id_for_ciphertext(ciphertext),
        seal.get_scale_for_ciphertext(ciphertext),
        'plaintext2'
    )
    ciphertext2 = seal.encryptor_encrypt(plaintext2, 'ciphertext2')
    seal.evaluator_add_inplace(ciphertext, ciphertext2)
    plaintext_sum = seal.decryptor_decrypt(ciphertext, 'plaintext_sum')
    print(f"Sum: {seal.ckks_decoder(plaintext_sum, 4)}")
    seal.clear_all_stored_pointers()


def ckks_example_2():
    print("===========Example: CKKS Basics II===========")
    # Demonstrating the power of rescaling
    seal = CythonWrapper("CKKS")
    seal.set_poly_modulus_degree(8192)
    seal.set_coeff_modulus(seal.default_coeff_modulus_128(8192))
    # Note here, plain_modulues congruent to 1 mod 2*ploy_modulus_degree, thus batching is enabled
    seal.initiate_seal()

    seal.relinearization_generate_keys(seal.default_dbc_max(), 1)
    seal.init_ckks_encoder()
    input = np.array([0.0, 1.1, 2.2, 3.3], dtype=np.double)
    print(f"Input vector {input}")
    scale = np.power(2, 60)
    plaintext = seal.ckks_encoder(input, scale, "plaintext")
    ciphertext = seal.encryptor_encrypt(plaintext, "ciphertext")
    print(f"Chain index of (encryption parameters of) encrypted: {seal.get_parms_id_for_ciphertext(ciphertext)}")
    print(f"Scale in ciphertext before squaring: {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    print(f"Scale in encrypted after squaring: {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")

    print("Rescaling")
    seal.evaluator_rescale_to_next_inplace(ciphertext)
    parms_id = seal.get_parms_id_for_ciphertext(ciphertext)
    print(f"Chain index of (encryption parameters of) encrypted: {parms_id}")
    print(f"Scale in ciphertext before squaring: {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")
    print(f"Coeff_modulus size: {seal.get_total_coeff_modulus_bit_count(parms_id)} bits")

    print("Squaring and rescaling")
    seal.evaluator_square_inplace(ciphertext)
    seal.evaluator_relinearize_inplace(ciphertext)
    seal.evaluator_rescale_to_next_inplace(ciphertext)
    parms_id = seal.get_parms_id_for_ciphertext(ciphertext)
    print(f"Chain index of (encryption parameters of) encrypted: {parms_id}")
    print(f"Scale in ciphertext before squaring: {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")
    print(f"Coeff_modulus size: {seal.get_total_coeff_modulus_bit_count(parms_id)} bits")

    print("Rescaling and squaring (no relinearization)")
    seal.evaluator_rescale_to_next_inplace(ciphertext)
    seal.evaluator_square_inplace(ciphertext)
    parms_id = seal.get_parms_id_for_ciphertext(ciphertext)
    print(f"Chain index of (encryption parameters of) encrypted: {parms_id}")
    print(f"Scale in ciphertext before squaring: {np.log2(seal.get_scale_for_ciphertext(ciphertext))} bits")
    print(f"Coeff_modulus size: {seal.get_total_coeff_modulus_bit_count(parms_id)} bits")

    decrypted_result = seal.decryptor_decrypt(ciphertext, "decrypted_result")
    result = seal.ckks_decoder(decrypted_result, 4)
    print(f"Precise result: {result}")
    seal.clear_all_stored_pointers()


def ckks_example_3():
    print("===========Example: CKKS Basics III===========")
    np.set_printoptions(precision=3)
    seal = CythonWrapper("CKKS")
    seal.set_poly_modulus_degree(8192)
    seal.set_coeff_modulus(np.array([
        seal.default_small_mods_40bit(0),
        seal.default_small_mods_40bit(1),
        seal.default_small_mods_40bit(2),
        seal.default_small_mods_40bit(3)
    ]))
    seal.initiate_seal()
    seal.init_ckks_encoder()
    seal.relinearization_generate_keys(seal.default_dbc_max(), 1)
    print(f"Number of slots: {seal.ckks_slot_count()}.")

    input = np.array(np.arange(4096)/(4096-1))
    print(f"Input vector: {input}, with size: {input.shape}")

    print(f"Evaluating polynomial PI*x^3 + 0.4x + 1 ...")
    scale = np.double(seal.default_small_mods_40bit(3))

    plain_x = seal.ckks_encoder(input, scale, 'plain_x')
    encrypted_x1 = seal.encryptor_encrypt(plain_x, 'encrypted_x1')

    plain_coeff0 = seal.ckks_encoder(np.ones(4096) * 1.0, scale, 'plain_coeff0')
    plain_coeff1 = seal.ckks_encoder(np.ones(4096) * 0.4, scale, 'plain_coeff1')
    plain_coeff3 = seal.ckks_encoder(np.ones(4096) * 3.14159265, scale, 'plain_coeff3')

    encrypted_x3 = seal.evaluator_square(encrypted_x1, 'encrypted_x3')
    seal.evaluator_relinearize_inplace(encrypted_x3)
    seal.evaluator_rescale_to_next_inplace(encrypted_x3)

    encrypted_x1_coeff3 = seal.evaluator_multiply_plain(encrypted_x1, plain_coeff3, 'encrypted_x1_coeff3')
    seal.evaluator_rescale_to_next_inplace(encrypted_x1_coeff3)

    seal.evaluator_multiply_inplace(encrypted_x3, encrypted_x1_coeff3)
    seal.evaluator_relinearize_inplace(encrypted_x3)
    seal.evaluator_rescale_to_next_inplace(encrypted_x3)

    seal.evaluator_multiply_plain_inplace(encrypted_x1, plain_coeff1)
    seal.evaluator_rescale_to_next_inplace(encrypted_x1)

    print("Parameters used by all three terms are different:")

    print(f"encrypted_x3 x3, "
          f"modulus chain index: {seal.get_parms_index(seal.get_parms_id_for_ciphertext(encrypted_x3))}, "
          f"scale: {np.log2(seal.get_scale_for_ciphertext(encrypted_x3))} bits")
    print(f"encrypted_x1 x1, "
          f"modulus chain index: {seal.get_parms_index(seal.get_parms_id_for_ciphertext(encrypted_x1))}, "
          f"scale: {np.log2(seal.get_scale_for_ciphertext(encrypted_x1))} bits")
    print(f"plain_coeff0, "
          f"modulus chain index: {seal.get_parms_index(seal.get_parms_id_for_plaintext(plain_coeff0))}, "
          f"scale: {np.log2(seal.get_scale_for_plaintext(plain_coeff0))} bits")

    seal.set_scale_for_ciphertext(encrypted_x3, seal.get_scale_for_ciphertext(encrypted_x1))

    seal.evaluator_mod_switch_to_inplace_ciphertext(encrypted_x1, seal.get_parms_id_for_ciphertext(encrypted_x3))
    seal.evaluator_mod_switch_to_inplace_plaintext(plain_coeff0, seal.get_parms_id_for_ciphertext(encrypted_x3))

    encrypted_result = seal.evaluator_add(encrypted_x3, encrypted_x1, "encrypted_result")
    seal.evaluator_add_plain_inplace(encrypted_result, plain_coeff0)

    print(f"encrypted_result, modulus chain index: {seal.get_parms_index(seal.get_parms_id_for_ciphertext(encrypted_result))}, scale: {np.log2(seal.get_scale_for_ciphertext(encrypted_result))} bits.")

    plain_result = seal.decryptor_decrypt(encrypted_result, "plain_result")
    result = seal.ckks_decoder(plain_result, 4096)
    print(f"Result of PI*x^3 + 0.4x + 1: {result[0:10]}")
    print(f"Current coeff_modulus size for encrypted_result {seal.get_total_coeff_modulus_bit_count(seal.get_parms_id_for_ciphertext(encrypted_result))}")
    seal.clear_all_stored_pointers()

def bfv_performance():
    print("===========BFV Performance Test===========")
    performance = CythonPerformance()
    performance.run_bfv_performance_test()


def ckks_performance():
    print("===========CKKS Performance Test===========")
    performance = CythonPerformance()
    performance.run_ckks_performance_test()
