FROM ubuntu:18.04
MAINTAINER Liyi Zhou <lzhou1110@gmail.com>

#
RUN apt-get -qqy update && apt-get install -qqy \
	g++ \
	git \
	make \
	python3 \
	python3-dev \
	python3-pip \
	sudo \
    libdpkg-perl \
    wget \
	--no-install-recommends


WORKDIR /cmake
RUN wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.tar.gz
RUN tar -xf cmake-3.10.0-Linux-x86_64.tar.gz
ENV PATH="/cmake/cmake-3.10.0-Linux-x86_64/bin:${PATH}"

WORKDIR /clang
RUN apt-get install -y software-properties-common sudo
# grab the key that LLVM use to GPG-sign binary distributions
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
RUN apt-get update
RUN apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-6.0 main"
RUN apt-get install -y clang-6.0 lld-6.0
RUN ln -s /usr/bin/clang-6.0 /usr/bin/clang
RUN ln -s /usr/bin/clang++-6.0 /usr/bin/clang++
RUN ln -s /usr/bin/llc-6.0 /usr/bin/llc


WORKDIR /
# SEAL require cmake >= 3.10
RUN cmake --version
# SEAL require gcc >= 6.0
RUN gcc --version
# SEAL require clang++ >= 5.0
RUN clang++ --version


ADD SEAL/. /app/SEAL
WORKDIR /app/SEAL/native/src
RUN cmake .
RUN make -j8
RUN make install

WORKDIR /
RUN pip3 install Cython==0.28.5
RUN pip3 install numpy==1.16.3

ADD CppWrapper/. /app/CppWrapper
WORKDIR /app/CppWrapper
RUN cmake .
RUN make -j8

WORKDIR /app
ADD examples.py /app
ADD utils.py /app
ADD app.py /app
ADD setup.py /app

ADD CythonWrapper/. /app/CythonWrapper

# cython_src setup
RUN python3 setup.py build_ext --inplace

# Run app.py
ENTRYPOINT ["python3"]
CMD ["-u", "app.py"]