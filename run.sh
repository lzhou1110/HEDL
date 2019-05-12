#!/usr/bin/env bash
docker build -t homomorphic_cython:latest .
docker run homomorphic_cython:latest