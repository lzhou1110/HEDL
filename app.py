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
    plain1_pointer = wrapper.integer_encoder(value1)
    plain1 = wrapper.plaintext_to_string(plain1_pointer)
    print("Encoded {} as polynomial {}".format(value1, plain1))

    value2 = -7
    plain2_pointer = wrapper.integer_encoder(value2)
    plain2 = wrapper.plaintext_to_string(plain2_pointer)
    print("Encoded {} as polynomial {}".format(value2, plain2))


def main():
    bfv_example_1()


if __name__ == '__main__':
    main()
