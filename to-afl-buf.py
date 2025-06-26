#!/usr/bin/env python3

import argparse
import os


def parse_args():
    global args
    parser = argparse.ArgumentParser(description='Convert AFL input to buf format.')
    parser.add_argument('input', type=str, help='Input file to convert')
    parser.add_argument('output', type=str, help='Output file in buf format')
    args = parser.parse_args()


def main():
    parse_args()

    size = os.stat(args.input).st_size

    with open(args.output, 'wb') as out_file, open(args.input, 'rb') as in_file:
        # Write the header
        out_file.write(size.to_bytes(4, byteorder='little'))

        # Write the content
        out_file.write(in_file.read())


if __name__ == '__main__':
    main()
