#!env python 


import argparse
import base64
import cPickle
import os
import random
import sys
from itertools import count
import zlib 

import png 

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FN_CHUNK = "iPFN"
DT_CHUNK = "iPFD"
CD_CHUNK = "mPDD"
SL_CHUNK = "mSLT"


class CantDecryptException(Exception):
    """
    Thrown if the key to decrypt the key chunk is wrong
    """
    pass

def generate_nkeys(n):
    """
    Generate n keys
    """
    keys = [Fernet.generate_key() for _ in xrange(0,n)]
    # This doesn't bring a lot of safety, better would be to support various more methods
    random.shuffle(keys)
    return keys


def rederive_key(key, salt):
    """
    Recalculate a derivated key  based on the salt and the password 
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(key))


def derive_key(key):
    """
    Calculate a key and generate a salt  
    """
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return (salt, base64.urlsafe_b64encode(kdf.derive(key)))



def append(args): 
    """
    Append files to an existing container 
    then reconstruct the png with the new keys attached
    """
    keys = generate_nkeys(len(args.files))
    random.shuffle(keys)
    (salt, key) = derive_key(args.key)
    fernet = Fernet(key)
    code_chunk = (CD_CHUNK, fernet.encrypt(cPickle.dumps(keys))) 
    salt_chunk = (SL_CHUNK, salt)

    with open(args.container, "r") as container: 
        reader = png.Reader(file=container)
        # This of course is horrible 
        # We should use a temp file, but for now it is fine  
        chunks = list(reader.chunks())
        (tend,iend) = chunks.pop() 
        if tend != "IEND":
            print "Muh suck"
            sys.exit(1)

        for (file,key) in zip(args.files,keys): 
            with open(file, "r") as hidee:
                name = file 
                data = hidee.read() 
                iname = (FN_CHUNK, name)
                fernet = Fernet(key)
                idata = (DT_CHUNK, fernet.encrypt(zlib.compress(data)))
                print "Packing %s" % (name) 
                chunks = chunks + [iname] + [idata]  
        with open(args.container + ".out", "w") as out: 
            chunks = chunks + [code_chunk] + [salt_chunk] + [(tend, iend)] 
            png.write_chunks(out, chunks)

def load_keys(key, chunks):
    """
    Load all the keys from file
    """
    keys = [] 
    deriv_key = None 
    salt = None 
    for chunk in chunks:
        (t,d) = chunk 
        if t == SL_CHUNK:
            salt = d 
            deriv_key = rederive_key(key, salt)
            break 

    fernet = Fernet(deriv_key)

    for chunk in chunks:
        (t,d) = chunk 
        if t == CD_CHUNK:

            try: 
                return cPickle.loads(fernet.decrypt(d))
            except InvalidToken:
                print "Wrong key, cannot decrypt key chunk"
                sys.exit(1)

    print "No key chunk found"
    sys.exit(1)




def containerGenerator(chunks):
    """
    Find all containers and there probable names and if not make one up
    """
    name = "undefined0"
    for (chunk, index) in zip(chunks, count(1)):
        (t,d) = chunk
        if t == FN_CHUNK:
            name = d
        elif t == DT_CHUNK:
            data = d
            print name 
            yield (name, data)
            name = "undefined%d" % index


def decryptChunk(keys, chunk):
    """
    Try to decrypt a chunk with one of the available keys
    """
    for key in keys:
        fernet = Fernet(key)
        try:
            return fernet.decrypt(chunk)
        except InvalidToken:
            pass
    raise CantDecryptException("Cannot decrypt chunk")

def extract(args):
    """
    Recover all the name chunks and data chunks and put them on disk. 
    Programs may reorder chunks at will, so it could be that all the names and data 
    are mixed up, however it will still output everything that is in the file. Just 
    invent names for them. 
    """
    with open(args.container, "r") as container:
        reader = png.Reader(file=container)
        chunks = list(reader.chunks())
        keys = load_keys(args.key, chunks)
        for (name, chunk) in containerGenerator(chunks):
            try: 
                decrypted = zlib.decompress(decryptChunk(keys, chunk))
                print "Unpacking %s to %s.out" % (name, name)
                with open("%s.out" % name, 'w') as out:
                    out.write(decrypted)
            except CantDecryptException:
                print "Cannot decrypt %s, wrong key or key not in key chunk"  % name 
            
def show(args):
   """
   List the files stored in the chunks 
   """
   with open(args.container, "r") as container:
        reader = png.Reader(file=container)
        chunks = reader.chunks()
        for (name, chunk) in containerGenerator(chunks):
            size = len(chunk)
            print "%s: %d bytes" % (name, size)

def main():
    """
    Parses arguments and runs the requested mode.   
    """
    parser = argparse.ArgumentParser(description="Store and retrieve objects from png images")

    parser.add_argument("-k", dest="key", required=True, action="store", help="Key to use for encryption")
    parser.add_argument("-c", dest="mode", action="store_const", const="append", help="add files to a png file")
    parser.add_argument("-x", dest="mode", action="store_const", const="extract", help="extract files from a png file")
    parser.add_argument("-t", dest="mode", action="store_const", const="list", help="list files in a png file")
    parser.add_argument("-f", required=True, dest="container", action="store", help="use file as container")
    parser.add_argument("files", nargs='*', help="files to add")

    args = parser.parse_args()

    if args.mode == "append":
        append(args)
    elif args.mode == "extract":
        extract(args)
    elif args.mode == "list":
        show(args)


main()
