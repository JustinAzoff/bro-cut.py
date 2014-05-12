#!/usr/bin/env python
import sys
import argparse
import datetime

DEFAULT_TIME_FMT="%Y-%m-%dT%H:%M:%S%z"

def extract_sep(line):
    return line.split(None, 1)[1].decode("string-escape")

def find_output_indexes(fields, columns, negate):
    if not columns:
        return list(range(len(fields)))

    field_mapping = dict((field, idx) for (idx, field) in enumerate(fields))

    if not negate:
        return [field_mapping.get(col) for col in columns]
    else:
        return [f for f in fields if f not in columns]

fromtimestamp = datetime.datetime.fromtimestamp
def convert_time(ts, fmt):
    ts = float(ts)
    t = fromtimestamp(ts)
    return t.strftime(fmt)


def bro_cut(f, columns, substtime=False, ofs="\t", negate=False):
    for line in f:
        if line.startswith("#"):
            if line.startswith("#separator"):
                sep = extract_sep(line)
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
                out_indexes = find_output_indexes(fields, columns, negate)
                out = [''] * len(out_indexes)
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
                time_fields = set(idx for (idx, t) in enumerate(types) if t == "time")
            continue

        parts = line.split()
        for out_idx, idx in enumerate(out_indexes):
            if idx != None:
                if substtime and idx in time_fields:
                    out[out_idx] = convert_time(parts[idx], substtime)
                else:
                    out[out_idx] = parts[idx]
            else:
                out[out_idx] = ''
        print ofs.join(out)

def main():

    parser = argparse.ArgumentParser(description='Bro cut.')
    parser.add_argument('-d', dest="substtime", action="store_const", const=DEFAULT_TIME_FMT,
        help='Convert time values into human-readable format')
    parser.add_argument('-D', dest='substtime',
        help='Like -d, but specify format for time (see strftime(3) for syntax)')

    parser.add_argument('-F', dest='ofs', default='\t',
        help='Sets a different output field separator.')

    parser.add_argument('-n', dest='negate', action="store_true",
        help='Print all fields *except* those specified.')

    parser.add_argument('columns', metavar='fields', nargs='*',
                   help='columns')

    args = parser.parse_args()

    bro_cut(sys.stdin, **vars(args))


if __name__ == "__main__":
    main()
