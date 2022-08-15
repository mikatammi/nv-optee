#!/usr/bin/env python3

# Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import codecs
import os.path
import struct
import sys

from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from math import ceil

def pkcs7_padding(plain_text):
    block_size = AES.block_size
    number_of_bytes_to_pad = block_size - len(plain_text) % block_size
    padding_str = number_of_bytes_to_pad * bytes([number_of_bytes_to_pad])
    padded_plain_text =  plain_text + padding_str
    return padded_plain_text

def ekb_cmac_gen(key, msg):
    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(msg)
    return c.finalize()

def ekb_encrypt(content, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(content) + encryptor.finalize()

def generateBlob(content, key_ek, key_ak):
    fmt = "<I8sxxxx"
    maxsize = 131072    # 128KB
    size = 0
    ekb_header_len = 16
    ekb_header_wo_size_field = 12
    contentmaxsize = maxsize - ekb_header_len

    if len(content) > contentmaxsize:
        raise Exception("Content is too big")

    if (len(content) % AES.block_size) != 0:
        content = pkcs7_padding(content)
    iv = os.getrandom(16, os.GRND_NONBLOCK)
    encrypted_content = ekb_encrypt(content, key_ek, iv)
    data = b"".join([iv, encrypted_content])
    ekb_cmac = ekb_cmac_gen(key_ak, data)

    ekb_size = len(ekb_cmac) + len(iv) + len(encrypted_content) + ekb_header_wo_size_field

    if ekb_size < 1024:
        pad_char = (1024 - ekb_size) % 256
        encrypted_content += bytes([pad_char]) * (1024 - ekb_size)

    # after padding
    eks_len = len(ekb_cmac) + len(iv) + len(encrypted_content) + ekb_header_wo_size_field
    header = struct.pack(fmt, eks_len, b"NVEKBP\0\0" )
    blob = header + ekb_cmac + iv + encrypted_content
    return blob

def nist_sp_800_108_with_CMAC(key, context=b"", label=b"", len=16):
    okm = b""
    output_block = b""
    for count in range(ceil(len/16)):
        data = b"".join([bytes([count+1]), label.encode(encoding="utf8"), bytes([0]), context.encode(encoding="utf8"), int(len*8).to_bytes(4, byteorder="big")])
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(data)
        output_block = c.finalize()
        okm += output_block
    return okm[:len]

def gen_ekb_rk(fuse_key, fv):
    rk = AES.new(fuse_key, AES.MODE_ECB)
    return rk.encrypt(fv)

def load_file_check_size(f, size=16):
    with open(f, 'rb') as fd:
        content = fd.read().strip()
        key = codecs.decode(content, 'hex')
        if len(key) != size:
            raise Exception("Wrong size")
        return key

def main():
    global verbose

    parser = argparse.ArgumentParser(description='''
    Generates EKB image by using KEK2 or OEM_K2 derived key to encrypt data from user's sym keys files.
    Each sym key file includes one user-defined symmetric key.
    ''')

    parser.add_argument('-chip', nargs=1, required=False, help="specify chip: t194|t234. default: t194")
    parser.add_argument('-kek2_key', nargs=1, required=False, help="kek2 key (16 bytes) file in hex format [t194 only]")
    parser.add_argument('-oem_k2_key', nargs=1, required=False, help="oem_k2 key (32 bytes) file in hex format [t234 only]")
    parser.add_argument('-fv', nargs=1, required=True, help="fixed vectors (16 bytes) files for EKB in hex format")
    parser.add_argument('-in_sym_key', nargs=1, required=True, help="16-byte symmetric key file in hex format")
    parser.add_argument('-in_sym_key2', nargs=1, required=True, help="16-byte symmetric key file in hex format")
    parser.add_argument('-out', nargs=1, required=True, help="where the eks image file is stored")

    args = parser.parse_args()
    if not all(map(os.path.exists, [args.fv[0], args.in_sym_key[0], args.in_sym_key2[0]])):
        raise Exception("fv, in_sym_key or in_sym_key2 files cannot be openned\n")

    chip = "t194"
    if args.chip != None:
        chip = args.chip[0]

    if chip == "t194":
        if args.kek2_key == None:
            raise Exception("kek2_key is not set")
        if not all(map(os.path.exists, [args.kek2_key[0]])):
            raise Exception("kek2_key file cannot be openned\n")
    elif chip == "t234":
        if args.oem_k2_key == None:
            raise Exception("oem_k2_key is not set")
        if not all(map(os.path.exists, [args.oem_k2_key[0]])):
            raise Exception("oem_k2_key file cannot be openned\n")
    else:
        raise Exception("Invalid chip: " + chip)

    # load fuse key
    if chip == "t194":
        fuse_key = load_file_check_size(args.kek2_key[0], 16)
    if chip == "t234":
        fuse_key = load_file_check_size(args.oem_k2_key[0], 32)

    # load fixed vector
    fv_ekb = load_file_check_size(args.fv[0])

    # generate root key
    ekb_rk = gen_ekb_rk(fuse_key, fv_ekb)

    # generate derived keys
    ekb_ek = nist_sp_800_108_with_CMAC(ekb_rk, "ekb", "encryption")
    ekb_ak = nist_sp_800_108_with_CMAC(ekb_rk, "ekb", "authentication")

    in_content = b""
    # load sym key file
    with open(args.in_sym_key[0], 'rb') as infd:
        tmp = infd.read().strip()
        in_content += codecs.decode(tmp, 'hex')

    with open(args.in_sym_key2[0], 'rb') as infd:
        tmp = infd.read().strip()
        in_content += codecs.decode(tmp, 'hex')

    # generate "eks.img"
    with open(args.out[0], 'wb') as f:
        f.write(generateBlob(in_content, ekb_ek, ekb_ak))

if __name__ == "__main__":
    main()

