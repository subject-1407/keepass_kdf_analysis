#!/usr/bin/env python3

import sys
import argparse
import hashlib
from Crypto.Cipher import AES
import time


def parse(file):
    with open(file, 'rb') as f:
        # skip signature
        f.read(12)

        # parse data
        while True:
            header_id = int.from_bytes(f.read(1), 'little')
            if header_id == 0:
                f.read(int.from_bytes(f.read(2), 'little'))
                encrypted_data = f.read(32)
                break
            elif header_id == 4:
                master_seed = f.read(int.from_bytes(f.read(2), 'little'))
            elif header_id == 5:
                transform_seed = f.read(int.from_bytes(f.read(2), 'little'))
            elif header_id == 6:
                transform_rounds = f.read(int.from_bytes(f.read(2), 'little'))
            elif header_id == 7:
                iv = f.read(int.from_bytes(f.read(2), 'little'))
            elif header_id == 9:
                stream_start_bytes = f.read(int.from_bytes(f.read(2), 'little'))
            else:
                f.read(int.from_bytes(f.read(2), 'little'))

    return master_seed, transform_seed, int.from_bytes(transform_rounds, 'little'), \
        iv, stream_start_bytes, encrypted_data


def read(wordlist):
    result = list()
    with open(wordlist, 'r') as f:
        for line in f:
            result.append(line.strip())
    return result


def sha256(data):
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def aes256(key, data, rounds=1, iv=None, mode='ECB'):
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        for i in range(rounds):
            data = cipher.encrypt(data)
        return data
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        for i in range(rounds):
            data = cipher.encrypt(data)
        return data


def create_key(password, master_seed, transform_seed, transform_rounds):
    if args.alternative:
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), master_seed, transform_rounds, 32)
    else:
        credentials = sha256(sha256(password.encode('utf-8')))
        transformed_credentials = sha256(aes256(transform_seed, credentials, rounds=transform_rounds))
        key = sha256(master_seed + transformed_credentials)
    return key


def main(database, wordlist=None):
    # parse database
    master_seed, transform_seed, transform_rounds, iv, stream_start_bytes, encrypted_data = parse(database)

    # prints header results in appropriate format
    if args.verbose:
        print(f'''
master_seed:        {hex(int.from_bytes(master_seed, 'little'))}
transform_seed:     {hex(int.from_bytes(transform_seed, 'little'))}
transform_rounds:   {transform_rounds}
encryption_iv:      {hex(int.from_bytes(iv, 'little'))}
stream_start_bytes: 0x{stream_start_bytes.hex()}
encrypted_data:     0x{encrypted_data.hex()}
''')

    # read wordlist if necessary
    if wordlist:
        passwords = read(wordlist)
    else:
        passwords = [str(x).zfill(4) for x in range(10000)]

    # bruteforce with passwords
    for password in passwords:
        # try password
        if aes256(create_key(password, master_seed, transform_seed, transform_rounds),
                  stream_start_bytes, iv=iv, mode='CBC') == encrypted_data:
            print(f'[+] GOT IT: {password}')
            break
        # print failed passwords for verbose option
        elif args.verbose:
            print(f'[-] {password}')


def measure(database, seconds):
    # parse database
    master_seed, transform_seed, transform_rounds, iv, stream_start_bytes, encrypted_data = parse(database)

    # not really necessary for measuring but maybe we luck out
    passwords = [str(x).zfill(4) for x in range(10000)]

    print(f'Measuring the passwords that can be checked in {seconds} second(s)...')
    # set variables for measuring time
    counter = 0
    current = time.time()

    for password in passwords:
        # try password
        if aes256(create_key(password, master_seed, transform_seed, transform_rounds),
                  stream_start_bytes, iv=iv, mode='CBC') == encrypted_data:
            # again, irrelevant for this but maybe we hit
            print(f'[+] GOT IT: {password}')
        # print failed passwords for verbose option
        elif args.verbose:
            print(f'[-] {password}')

        # halt condition for time measurement
        if time.time() > current + int(seconds):
            print(f'{counter} passwords checked!')
            break
        else:
            counter += 1


def corrupt(database, password):
    master_seed, transform_seed, transform_rounds, iv, stream_start_bytes, encrypted_data = parse(database)
    print(f'''
original stream_start_bytes:    0x{stream_start_bytes.hex()}
original encrypted_ss_bytes:    0x{encrypted_data.hex()}

corrupted stream_start_bytes:   0x{('0' * 64)}
corrupted encrypted_ss_bytes:   0x{aes256(create_key(password, master_seed, transform_seed, transform_rounds),
                                          bytes.fromhex(('0' * 64)), iv=iv, mode='CBC').hex()}
''')


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Break the password of a keepass database. Defaults to 4-digit pins.')
    parser.add_argument('database', help='database file to use')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('-w', '--wordlist', help='use wordlist of passwords to use')
    parser.add_argument('-m', '--measure', metavar='SECONDS',
                        help='measure number of passwords which can be tested in given seconds')
    parser.add_argument('-c', '--corrupt', metavar='PASSWORD',
                        help='calculates encrypted_stream_start_bytes of stream_start_bytes = 0x0 for given password. This can be used to create a modified but still valid second database file.')
    parser.add_argument('-a', '--alternative', action='store_true',
                        help='alternative mode using pbkdf2-hmac-sha256 to calculate key')
    args = parser.parse_args()
    # args.verbose and args.alternative get handled as global flags

    if args.corrupt:
        corrupt(args.database, args.corrupt)
    elif args.measure:
        measure(args.database, args.measure)
    else:
        main(args.database, wordlist=args.wordlist)
