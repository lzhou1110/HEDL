from CythonWrapper.cythonwrapper import CythonWrapper
import numpy as np



def bfv_example_1():
    wrapper = CythonWrapper(bytes("BFV", 'utf-8'), 128, 2048, 2048, np.power(2, 8))
    wrapper.print_seal_version()
    wrapper.print_allocated_memory()
    wrapper.print_parameters()

    # Using integer encoder
    wrapper.init_integer_encoder()

    value1 = 5
    value2 = -7
    plain1 = wrapper.integer_encoder(value1, bytes('plain1', 'utf-8'))
    plain2 = wrapper.integer_encoder(value2, bytes('plain2', 'utf-8'))
    print("Encoded {} as polynomial {}".format(value1, wrapper.plaintext_to_string(plain1)))
    print("Encoded {} as polynomial {}".format(value2, wrapper.plaintext_to_string(plain2)))

    cipher1 = wrapper.encryptor_encrypt(plain1, bytes('cipher1', 'utf-8'))
    cipher2 = wrapper.encryptor_encrypt(plain2, bytes('cipher2', 'utf-8'))
    print("Noise budget in encrypted1: {} bits".format(wrapper.decryptor_invariant_noise_budget(cipher1)))
    print("Noise budget in encrypted2: {} bits".format(wrapper.decryptor_invariant_noise_budget(cipher2)))

    wrapper.evaluator_add_inplace(cipher1, cipher2)
    print("Noise budge in encrypted1 + encrypted2: {} bits"
          .format(wrapper.decryptor_invariant_noise_budget(cipher1)))

    plain_result = wrapper.decryptor_decrypt(cipher1, bytes('plain_result', 'utf-8'))
    print(wrapper.integer_decoder(plain_result))
    wrapper.clear_all_stored_pointers()