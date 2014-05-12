#!/usr/bin/env python
import sys
import argparse

DEFAULT_TIME_FMT="%Y-%m-%dT%H:%M:%S%z"


def reader(f):
    line = ''
    headers = {}
    it = iter(f)
    while not line.startswith("#types"):
        line = next(it).rstrip()
        k,v = line[1:].split(None, 1)
        headers[k] = v

    sep = headers['separator'].decode("string-escape")

    for k,v in headers.items():
        if sep in v:
            headers[k] = v.split(sep)

    headers['separator'] = sep
    fields = headers['fields']
    types = headers['types']
    set_sep = headers['set_separator']

    vectors = [field for field, type in zip(fields, types) if type.startswith("vector[")]

    for row in it:
        if row.startswith("#close"): break
        parts = row.rstrip().split(sep)
        rec = dict(zip(fields, parts))
        for f in vectors:
            rec[f] = rec[f].split(set_sep)
        yield rec

def bro_cut(columns=None, ofs="\t", negate=False, substtime=DEFAULT_TIME_FMT):
    if columns is None:
        columns = []
    else:
        columns = set(columns)

    for rec in reader(sys.stdin):
        print rec

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

    print args

    bro_cut(**vars(args))


if __name__ == "__main__":
    main()
