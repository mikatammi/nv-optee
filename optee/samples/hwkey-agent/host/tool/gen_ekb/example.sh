#!/bin/bash

# [T194 example]
# This is default KEK2 root key for unfused board
echo "00000000000000000000000000000000" > kek2.key

# This is the default initial vector for EKB.
echo "bad66eb4484983684b992fe54a648bb8" > fv_ekb_t194

# Generate user-defined symmetric key files
# openssl rand -rand /dev/urandom -hex 16 > sym_t194.key
# openssl rand -rand /dev/urandom -hex 16 > sym2_t194.key
echo "00000000000000000000000000000000" > sym_t194.key
echo "00000000000000000000000000000000" > sym2_t194.key

python3 gen_ekb.py -chip t194 -kek2_key kek2.key \
        -fv fv_ekb_t194 \
        -in_sym_key sym_t194.key \
        -in_sym_key2 sym2_t194.key \
        -out eks_t194.img

# [T234 example]
# Fill your OEM_K2 fuse key value
echo "432646294a404e635266556a586e3272357538782f413f442a472d4b61506453" > oem_k2.key

# This is the default initial vector for EKB.
echo "bad66eb4484983684b992fe54a648bb8" > fv_ekb_t234

# Generate user-defined symmetric key files
# openssl rand -rand /dev/urandom -hex 16 > sym_t234.key
# openssl rand -rand /dev/urandom -hex 16 > sym2_t234.key
echo "010203040506070809a0b0c0d0e0f001" > sym_t234.key
echo "f0e0d0c0b0a001020304050607080900" > sym2_t234.key

python3 gen_ekb.py -chip t234 -oem_k2_key oem_k2.key \
        -fv fv_ekb_t234 \
        -in_sym_key sym_t234.key \
        -in_sym_key2 sym2_t234.key \
        -out eks_t234.img
