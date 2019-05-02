from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

seal_dirs = ["SEAL/native/src", "SEAL/native/src/util", "CppWrapper"]

extensions = [
    Extension(
        "CythonWrapper.cythonwrapper",
        ["CythonWrapper/cythonwrapper.pyx"],
        include_dirs=seal_dirs,
        libraries = ["seal"],
        language="c++",
        extra_compile_args=["-std=c++17", "-O3", "-DHAVE_CONFIG_H"]
    ),
]

setup(
    name="HEDL",
    ext_modules=cythonize(extensions),
)
