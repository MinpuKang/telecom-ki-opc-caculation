#!/usr/bin/env python3
#_*_ coding:utf-8 _*_
#Version: 1.0
#Author: Minpu Kang
#Create Date: 2023-11-04
#Options: This is implementation of generating OPc based on OPc=AES128(Ki,OP) XOR OP, OPc=Encypt-Algo(OP,Key) OPc -[128 Bits]
#        1.0 2023-11-04 First version
#        2.0 2026-11-10 fix the OPc not 32 digit issue sometime.

from Crypto.Cipher import AES
from binascii import unhexlify
import codecs
import argparse
import os
import sys


def fprint(text, variable):
    print(f'{text}{variable}')

def x_o_r(byte1, byte2):
    return hex(byte1 ^ byte2)

def opc_generating(mode, key, op):
    # convert to binary
    byte_key = unhexlify(key)
    byte_op = unhexlify(op)
    # select mode to ecb
    cipher = AES.new(byte_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(byte_op)
    # convert to hex
    last_data = codecs.encode(encrypted_data, 'hex')
    opc_raw = x_o_r(int(bytes.decode(last_data), 16), int(op, 16))
    opc = opc_raw[2:].upper().zfill(len(op))
    
    fprint('Formula: ', 'OPc=AES128(Ki,OP) XOR OP')
    fprint('Ki: ', key.upper()+" (Length "+str(len(key))+")")
    fprint('OP: ', op.upper()+" (Length "+str(len(op))+")")
    fprint('OPc: ', opc.upper()+" (Length "+str(len(opc))+")")

if __name__ == '__main__':
    def add_common_arguments(parser):
        parser.add_argument('-ki', dest='key', type=str, help='Ki value to be used for generating OPc')
        parser.add_argument('-op', dest='op', type=str, help='OP value to be used for generating OPc')
        
        return parser
        
    basename=os.path.abspath(__file__)
    if len(sys.argv) == 1:
        fprint("Errror: ", "Mandatory paramter missed!\n")
        os.system("python \"%s\" -h" %basename)
        sys.exit()
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest='mode')
    opc_parser = add_common_arguments(
        sub_parsers.add_parser('opc', help='Generate OPc'))
    
    args = parser.parse_args()
    
    if args.mode == 'opc':
        if args.key is None or args.op is None:
            fprint("Errror: ", "key or OP must be required!\n")
            os.system("python \"%s\" opc -h" %basename)
            sys.exit()
        else:
            if len(args.op) != 32:
                fprint("Errror: ", "The length of OP should be 32!")
                fprint("Input OP Lengh: ", len(args.op))
                sys.exit()
            if len(args.key) != 32:
                fprint("Errror: ", "The length of Ki should be 32!")
                fprint("Input Ki Lengh: ", len(args.key))
                sys.exit()
            opc_generating(args.mode, args.key, args.op)
