# -*- coding: utf-8 -*-

import sys
import os
import logging
import logging.config
from functools import partial
from getpass import getpass
import re

from docopt import docopt
from nacl.public import PrivateKey

from . import __title__, __version__, PROG
from . import lib
from . import utils
from . import C4GHEXT, HEADEREXT
from .keys import get_public_key, get_private_key

LOG = logging.getLogger(__name__)

C4GH_DEBUG  = os.getenv('C4GH_DEBUG', False)
DEFAULT_SK  = os.getenv('C4GH_SECRET_KEY', None)
DEFAULT_LOG = os.getenv('C4GH_LOG', None)
 
__doc__ = f'''

Utility for the cryptographic GA4GH standard, reading from --inputfile/--inputheader (for single files) or --inputfilelist/--inputheaderlist (for a list of files) and outputting to --outputfile/--outputheader (for a single file) and to --outputfilelist/--outputheaderlist (for a list of files).

Usage:
  {PROG} [-hv] [--log <file>] encrypt [--sk <path>] (--inputfile <path> | --inputfilelist <path>) --recipient_pk <path> [--recipient_pk <path>]... [--range <start-end>] [--split-header] 
  {PROG} [-hv] [--log <file>] decrypt [--sk <path>] (--inputfile <path> | --inputfilelist <path>) [--sender_pk <path>] [--range <start-end>] [--split-header]
   {PROG} [-hv] [--log <file>] rearrange [--sk <path>] --range <start-end>
   {PROG} [-hv] [--log <file>] reencryptfile [--sk <path>] --recipient_pk <path> (--inputfile <path>|--inputfilelist <path>) (--outputfile <path>|--outputfilelist <path>) [--recipient_pk <path>]... [--trim] 
   {PROG} [-hv] [--log <file>] reencryptheader [--sk <path>] --recipient_pk <path> (--inputheader <path>|--inputheaderlist <path>) (--outputheader <path>|--outputheaderlist <path>) [--recipient_pk <path>]... [--trim] 

Options:
   -h, --help             Prints this help and exit
   -v, --version          Prints the version and exits
   --log <path>           Path to the logger file (in YML format)
   --sk <keyfile>         Curve25519-based Private key
                          When encrypting, if neither the private key nor C4GH_SECRET_KEY are specified, we generate a new key 
   --inputfile <path>     Input file to be encrypted/decrypted
   --inputfilelist <path> Input file list to be encrypted/decrypted
   --inputheader <path>   Input header  to be encrypted/decrypted
   --inputheaderlist <path>   Input header list to be encrypted/decrypted
   --outputfile <path>    Output file 
   --outputfilelist <path>    Output file list
   --outputheader <path>  Output header file
   --outputheaderlist <path>  Output header file list
   --recipient_pk <path>  Recipient's Curve25519-based Public key
   --sender_pk <path>     Peer's Curve25519-based Public key to verify provenance (akin to signature)
   --range <start-end>    Byte-range either as  <start-end> or just <start> (Start included, End excluded)
   -t, --trim             Keep only header packets that you can decrypt
   --split-header         Separate the header from the payload during encryption and create a separate .header file

Environment variables:
   C4GH_LOG         If defined, it will be used as the default logger
   C4GH_SECRET_KEY  If defined, it will be used as the default secret key (ie --sk ${{C4GH_SECRET_KEY}})
   C4GH_PASSPHRASE  If defined, it will be used as the passphrase
                    for decoding the secret key, replacing the callback.
                    Note: this is insecure. Only used for testing
   C4GH_DEBUG       If True, it will print (a lot of) debug information.
                    (Watch out: the output contains secrets)
 
'''

def parse_args(argv=sys.argv[1:]):

    version = f'{__title__} (version {__version__})'
    args = docopt(__doc__, argv, help=True, version=version)

    # Logging
    logger = args['--log']  or DEFAULT_LOG
    _stream = open(logger, "wt") if logger!=None else sys.stderr.buffer
    # for the root logger
    logging.basicConfig(stream=_stream,
                        level=logging.DEBUG if C4GH_DEBUG else logging.CRITICAL,
                        format='[%(levelname)s] %(message)s')

    # I prefer to clean up
    for s in ['--log', '--help', '--version']:#, 'help', 'version']:
        del args[s]

    # split header parameter
    splitheader=args['--split-header'] 
    
    # check incompatible parameter (example : you can't use a single input file and a list of output files)
    incompatible_params={'--inputfile':['--inputfilelist','--inputheaderlist','--outputfilelist','--outputheaderlist'],
                         '--outputfile':['--inputfilelist','--inputheaderlist','--outputfilelist','--outputheaderlist'],
                         '--inputfilelist':['--inputfile','--inputheader','--outputfile','--outputheader'],
                         '--inputheaderlist':['--inputfile','--inputheader','--outputfile','--outputheader'],
                         '--outputheaderlist':['--inputfile','--inputheader','--outputfile','--outputheader']}

    # throw error message if two incompatible parameters are used at the same time
    for k,vals in incompatible_params.items():
        for v in vals:
            if (args[k]!=None) and (args[v]!=None):
                print(f"Error : parameters {k} and {v} cannot be used at the same time !")
                sys.exit(-1)

    # check if we're working on one file or a list of files
    args['singlefilemode'] = True if (args['--inputfilelist']==None and args['--inputheaderlist']==None) else False

    # set input/output parameters 
    input_params = []
    output_params = []

    if  (args['encrypt'] or args['decrypt']) and args['singlefilemode']:
        input_params = ['--inputfile']
    elif (args['encrypt'] or args['decrypt']) and (not args['singlefilemode']):
        input_params = ['--inputfilelist']
    elif args['reencryptfile'] and args['singlefilemode']: # reencrypt file (without split header)
        input_params = ['--inputfile']
        output_params = ['--outputfile']
    elif args['reencryptfile'] and (not args['singlefilemode']) : # reencrypt list of files (without split headers)
        input_params = ['--inputfilelist'] 
        output_params = ['--outputfilelist']
    elif args['reencryptheader'] and args['singlefilemode']: # reencrypt header file 
        input_params = ['--inputheader']
        output_params = ['--outputheader'] 
    elif args['reencryptheader'] and (not args['singlefilemode']): # reencrypt list of headers
        input_params = ['--inputheaderlist'] 
        output_params = ['--outputheaderlist']  

    mandatory_params = input_params + output_params # all input + output parameters are mandatory 

    # check mandatory parameters
    for s in mandatory_params:
        if (not (s in args.keys())) or (args[s]==None):
            print(f"Error: argument {s} missing !", file=sys.stderr)
            sys.exit(-1)

    # check input parameters exist
    for s in input_params:
        utils.check_input_file_exists(args[s])

    # check output parameters exists 
    for s in output_params:
        if not("list" in s):
            utils.check_output_file_exists(args[s])

    # check lines count if w're processing a list of files
    if (not args['singlefilemode']) and (args['reencryptheader'] or args['reencryptfile']):
        files_to_check=[args[s] for s in mandatory_params] # list of files to check (they should be non-empty and have the same number of lines)
        (nblines, samecount) = utils.check_valid_lines_count(files_to_check)

        if not samecount:
            print(f"Error : input/output file lists should have the same number of lines (check these files : {files_to_check}) !")
            sys.exit(-1)

        # check whether all output files do not already exists 
        outputfiles= utils.read_files_list(args['--outputfilelist']) + utils.read_files_list(args['--outputheaderlist'])
        for f in outputfiles:
            if os.path.exists(f):
                print(f"Error: output file {f} already exists !", file=sys.stderr)
                sys.exit(-1)

        args['nbfiles']=nblines

    args["inputparams"]=input_params
    args["outputparams"]=output_params

    return args


range_re = re.compile(r'([\d]+)-([\d]+)?')

def parse_range(args):
    r = args['--range']
    if not r:
        return (0, None)

    m = range_re.match(r)
    if m is None:
        raise ValueError(f"Invalid range: {args['--range']}")
    
    start, end = m.groups()  # end might be None
    start, end = int(start), (int(end) if end else None)
    span = end - start - 1 if end else None
    if not span:
        raise ValueError(f"Invalid range: {args['--range']}")
    return (start, span)

def retrieve_private_key(args, generate=False):

    seckey = args['--sk'] or DEFAULT_SK

    if generate and seckey is None: # generate a one on the fly
        sk = PrivateKey.generate()
        skey = bytes(sk)
        LOG.debug('Generating Private Key: %s', skey.hex().upper())
        return skey

    seckeypath = os.path.expanduser(seckey)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    return get_private_key(seckeypath, cb)

def encrypt(args):
    assert( args['encrypt'] )

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args, generate=True)

    def build_recipients():
        for pk in args['--recipient_pk']:
            recipient_pubkey = os.path.expanduser(pk)
            if not os.path.exists(recipient_pubkey):
                print(f"Recipient pubkey: {recipient_pubkey}, does not exist", file=sys.stderr)
                continue
            LOG.debug("Recipient pubkey: %s", recipient_pubkey)
            yield (0, seckey, get_public_key(recipient_pubkey))

    # keys = list of (method, privkey, recipient_pubkey=None)
    # using a set now, instead of inside the generator loop
    # because we'd remove repetition in case different filenames are used for the same key
    recipient_keys = set(build_recipients()) # must have at least one, remove repetitions
    if not recipient_keys:
        raise ValueError("No Recipients' Public Key found")

    # prepare input/output parameters list (the list contains one element if we are in 'singlefilemode')
    splitheader=args['--split-header'] 

    inputfileslist=None
    if args['singlefilemode']:
        inputfileslist=[args['--inputfile']]
    else:
        inputfileslist=utils.read_files_list(args['--inputfilelist'])

    # loop over files to be processed
    for inputfilename in inputfileslist:
        utils.check_input_file_exists(inputfilename)
        outputfilename=utils.add_extension(inputfilename,C4GHEXT)
        outputheadername=None if (not splitheader) else utils.add_extension(inputfilename,HEADEREXT)

        if outputheadername:
            utils.check_output_file_exists(outputheadername)

        utils.check_output_file_exists(outputfilename)  
        msg=f"Encrypting file {inputfilename} and saving header into {outputheadername} .." if splitheader else f"Encrypting file {inputfilename} .."
        print(msg)
        lib.encrypt(recipient_keys,inputfilename,outputfilename,outputheadername,splitheader,offset = range_start,span = range_span)


def decrypt(args):
    assert( args['decrypt'] )

    sender_pubkey = get_public_key(os.path.expanduser(args['--sender_pk'])) if args['--sender_pk'] else None

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, None)] # keys = list of (method, privkey, recipient_pubkey=None)

    # prepare input/output parameters list (the list contains one element if we are in 'singlefilemode')
    splitheader=args['--split-header'] 

    inputfileslist=None 
    if not args['singlefilemode']: 
        inputfileslist=utils.read_files_list(args['--inputfilelist'])
    else:
        inputfileslist=[args['--inputfile']]
        
    # loop over files to be processed 
    for inputfilename in inputfileslist:
        utils.check_input_file_exists(inputfilename)
        outputfilename = utils.remove_extension(inputfilename, C4GHEXT)
        inputheadername = None if (not splitheader) else utils.add_extension(outputfilename,HEADEREXT)

        if inputheadername:
            utils.check_input_file_exists(inputheadername)

        utils.check_output_file_exists(outputfilename) 

        msg=f"Decrypting file {inputfilename} with header {inputheadername} .." if splitheader else f"Decrypting file {inputfilename} .." 
        print(msg)
        lib.decrypt(keys, inputfilename, inputheadername, outputfilename, splitheader, offset = range_start, span = range_span, sender_pubkey=sender_pubkey)


def rearrange(args):
    assert( args['rearrange'] )

    range_start, range_span = parse_range(args)

    seckey = retrieve_private_key(args)

    keys = [(0, seckey, bytes(PrivateKey(seckey).public_key))] # keys = list of (method, privkey, recipient_pubkey=ourselves)

    lib.rearrange(keys,
                  sys.stdin.buffer,
                  sys.stdout.buffer,
                  offset = range_start,
                  span = range_span)


def reencrypt(args):

    seckey = retrieve_private_key(args)

    def build_recipients():
        for pk in args['--recipient_pk']:
            recipient_pubkey = os.path.expanduser(pk)
            if not os.path.exists(recipient_pubkey):
                print(f"Recipient pubkey: {recipient_pubkey}, does not exist", file=sys.stderr)
                continue
            LOG.debug("Recipient pubkey: %s", recipient_pubkey)
            yield (0, seckey, get_public_key(recipient_pubkey))

    # keys = list of (method, privkey, recipient_pubkey=None)
    # using a set now, instead of inside the generator loop
    # because we'd remove repetition in case different filenames are used for the same key
    recipient_keys = set(build_recipients()) # must have at least one, remove repetitions
    if not recipient_keys:
        raise ValueError("No Recipients' Public Key found")

    # prepare input/output parameters list (the list contains one element if we are in 'singlefilemode')
    splitheader=args['--split-header']

    if splitheader:
        inputfilename_list=[args['--inputheader']] if args['singlefilemode']  else utils.read_files_list(args['--inputheaderlist'])
        outputfilename_list=[args['--outputheader']] if args['singlefilemode']  else utils.read_files_list(args['--outputheaderlist'])
    else:
        inputfilename_list=[args['--inputfile']] if args['singlefilemode']  else utils.read_files_list(args['--inputfilelist'])
        outputfilename_list=[args['--outputfile']] if args['singlefilemode']  else utils.read_files_list(args['--outputfilelist']) 

    # loop over files to be processed 
    for (inputfilename,outputfilename) in zip(inputfilename_list,outputfilename_list):
        msg=f"Re-encrypting header file {inputfilename} .." if splitheader else f"Re-encrypting file {inputfilename} .."
        print(msg)
        lib.reencrypt([(0, seckey, None)], recipient_keys, inputfilename, outputfilename, splitheader, trim=args['--trim'])


def reencryptfile(args):
    assert( args['reencryptfile'] )
    args['--split-header']=False
    reencrypt(args)

def reencryptheader(args):
    assert( args['reencryptheader'] )
    args['--split-header']=True
    reencrypt(args)


