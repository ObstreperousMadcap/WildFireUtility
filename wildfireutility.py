#!/usr/bin/python3

# Copyright (c) 2023 Michael Logan <ObstreperousMadcap@soclab.tech>
# Uses original work copyrighted (c) 2013-2019 Kevin Steves <kevin.steves@pobox.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Version    Date        Notes
# 1.0        2023-09-15  "Initial" release. Not *really* the first, but the first one with a version number.

from datetime import datetime
from pathlib import Path

import csv
import getopt
import signal
import ssl
import string
import sys

import pan.wfapi
import pan.config

def main():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except AttributeError:
        # Windows
        pass

    options = parse_options()
    if options['api-key'] is None:
        usage()
        sys.exit(0)
        
    starttime = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    try:
        wfapi = pan.wfapi.PanWFapi(tag=None,
                                   api_key=options['api-key'],
                                   hostname=None,
                                   timeout=options['timeout'],
                                   http=False,
                                   ssl_context=ssl._create_unverified_context())
    
        if options['submit-files'] is not None:
            submit_files(wfapi, options, starttime)    
        elif (options['verdicts-hashfile'] is not None) or (options['verdicts-submitlog'] is not None):
            query_verdicts(wfapi, options, starttime)
        elif (options['reports-hashfile'] is not None) or (options['reports-submitlog'] is not None):
            download_reports(wfapi, options, starttime)

    except pan.wfapi.PanWFapiError as msg:
        print('pan.wfapi.PanWFapi:' + str(msg), file=sys.stderr)
        sys.exit(1)
        
    sys.exit(0)

def submit_files(wfapi, options, starttime):
    kwargs = {}
    results = {}
    panconfig = {}    
    
    filepath = options['submit-files']
    if Path(filepath).is_dir():       
        print("Enumerating files in '" + filepath + "'")
        for filename in Path(filepath).iterdir():
            if not Path(filename).name.startswith('.'): # Exclude hidden files on Linux/macOS
                if Path(filename).is_file():
                    results[Path(filename).name] = {}
    else: 
        print("Error: '" + filepath + "' is not a valid path")
        return

    print("Submitting files to WildFire")

    for filename in results:
        kwargs['file'] = str(Path(filepath) / filename)
        try:
            wfapi.submit(**kwargs)
            if wfapi.http_code is not None:
                results[filename]['http_code'] = wfapi.http_code
            if wfapi.http_reason is not None:
                results[filename]['http_reason'] = wfapi.http_reason
            if "200" in str(wfapi.http_code):
                panconfig = get_panconfig(wfapi)
                if panconfig:
                    results[filename]['sha256'] = panconfig['wildfire']['upload-file-info']['sha256']
                else:
                    results[filename]['sha256'] = ""
                print("\t", filename, ":", results[filename]['http_reason'])
        except pan.wfapi.PanWFapiError:
            results[filename]['http_code'] = wfapi.http_code
            results[filename]['http_reason'] = wfapi.http_reason

    logfilename = Path(filepath).parent / str("WildFireSubmissionsLogfile-" + starttime + ".csv")
    fields = ['filename', 'sha256' , 'http_code', 'http_reason']
    save_logfile(logfilename, fields, results)

def query_verdicts(wfapi, options, starttime):
    verdicts = {'0' : 'benign', 
                '1' : 'malware', 
                '2' : 'grayware',
                '4' : 'phishing',
                '5' : 'C2',
                '-100' : 'pending; the sample exists, but there is currently no verdict',
                '-101' : 'error',
                '-102' : 'unknown; cannot find sample record in the database',
                '-103' : 'invalid hash value'
                }    
    kwargs = {}
    hashlist = []
    results = {}
    panconfig = {}
    
    if options['verdicts-hashfile'] is not None:
        if not enumerate_hashes(options['verdicts-hashfile'], True, hashlist, results):
            return False
        else:
            logfilepath = Path(Path(options['verdicts-hashfile']).parent).name
    elif options['verdicts-submitlog'] is not None:
        if not enumerate_hashes(options['verdicts-submitlog'], False, hashlist, results):
            return False
        else:
            logfilepath = Path(Path(options['verdicts-submitlog']).parent).name
    else:
        return False

    print("Querying WildFire for verdicts")

    for hash in hashlist:
        if not check_hash(hash):
            results[hash]['http_reason'] = "hash length/characters invalid"
            results[hash]['verdict'] = 'bad hash'
        else:
            kwargs['hash'] = hash
            try:
                wfapi.verdict(**kwargs)
                if wfapi.http_code is not None:
                    results[hash]['http_code'] = wfapi.http_code
                if wfapi.http_reason is not None:
                    results[hash]['http_reason'] = wfapi.http_reason
                if "200" in str(wfapi.http_code):
                    panconfig = get_panconfig(wfapi)
                    if panconfig:
                        results[hash]['verdict'] = verdicts[panconfig['wildfire']['get-verdict-info']['verdict']]
                    else:
                        results[hash]['verdict'] = ""
                    if not results[hash]['filename'] == "":                
                        print("\t", results[hash]['filename'], ":", results[hash]['verdict'])
                    else:
                        print("\t", hash, ":", results[hash]['verdict'])                        
            except pan.wfapi.PanWFapiError:
                results[hash]['http_code'] = wfapi.http_code
                results[hash]['http_reason'] = wfapi.http_reason

    logfilename = Path(logfilepath) / str("WildFireVerdictsLogfile-" + starttime + ".csv")

    fields = [ 'sha256', 'filename', 'verdict', 'http_code', 'http_reason']
    save_logfile(logfilename, fields, results)
    
    return True

def download_reports(wfapi, options, starttime):
    kwargs = {}
    hashlist = []
    results = {}
    
    if options['reports-hashfile'] is not None:
        if not enumerate_hashes(options['reports-hashfile'], True, hashlist, results):
            return False
        else:
            reportfolder = (Path(options['reports-hashfile']).parent) / str("WildFireReports-" + starttime)
    elif options['reports-submitlog'] is not None:
        if not enumerate_hashes(options['reports-submitlog'], False, hashlist, results):
            return False
        else:
            reportfolder = (Path(options['reports-submitlog']).parent) / str("WildFireReports-" + starttime)
    else:
        return False
                
    Path(reportfolder).mkdir()
    print("Querying WildFire for report(s); Saving report(s) in", Path(reportfolder))

    for hash in hashlist:
        if not check_hash(hash):
            results[hash]['http_reason'] = "hash length/characters invalid"
            results[hash]['report_filename'] = 'bad hash'
        else:
            kwargs['hash'] = hash
            kwargs['format'] = "pdf"
            
            try:
                wfapi.report(**kwargs)
                if wfapi.http_code is not None:
                    results[hash]['http_code'] = wfapi.http_code
                if wfapi.http_reason is not None:
                    results[hash]['http_reason'] = wfapi.http_reason
                if "200" in str(wfapi.http_code):
                    results[hash]['report_filename'] = wfapi.attachment['filename']
                    save_reportfile(wfapi, reportfolder)
                    if not results[hash]['filename'] == "":
                        print("\t", results[hash]['filename'], ":", results[hash]['report_filename'])
                    else:
                        print("\t", hash, ":", results[hash]['report_filename'])
            except pan.wfapi.PanWFapiError:
                results[hash]['http_code'] = wfapi.http_code
                results[hash]['http_reason'] = wfapi.http_reason
        
    logfilename = Path(reportfolder) / str("WildFireReportsLogfile-" + starttime + ".csv")
    fields = [ 'sha256', 'filename', 'report_filename', 'http_code', 'http_reason']
    save_logfile(logfilename, fields, results)
    
    return True

def save_reportfile(wfapi, reportfolder):
    if wfapi.attachment is None:
        return

    reportfilename = Path(reportfolder) / Path(wfapi.attachment['filename'])
    
    try:
        filewriter = open(reportfilename, 'wb')
    except IOError as msg:
        print('Error opening %s: %s' % (reportfilename, str(msg)), file=sys.stderr)
        return

    try:
        filewriter.write(wfapi.attachment['content'])
    except IOError as msg:
        print('Error writing %s: %s' % (reportfilename, str(msg)), file=sys.stderr)
        filewriter.close()
        return

    filewriter.close()

def enumerate_hashes(filename, hashfile, hashlist, results):
    print("Enumerating hashes in '" + filename + "'")
    if Path(filename).is_file:   
        if hashfile:
            with open(filename) as file:
                while (line := file.readline().rstrip()):
                    results[line] = {}
                    results[line]['filename'] = ""
                    hashlist.append(line)
        else:
            with open(filename, 'r') as data_file:
                filereader = csv.DictReader(data_file, delimiter=',')
                for row in filereader:
                    if row['sha256']:
                        results[row['sha256']] = {}
                        results[row['sha256']]['filename'] = row['filename']
                        hashlist.append(row['sha256'])
    else:
        print("Error: '" + filename + "'is not a valid file")
        return False
    
    return True

def check_hash(hash):
    if ((len(hash) == 64) and (set(hash) <= set(string.digits + string.ascii_lowercase[:6] + string.ascii_uppercase[:6]))):
        return True
    else:
        return False

def get_panconfig(wfapi):
    if wfapi.xml_element_root is None:
        print("Error: wfapi.xml_element_root")
        return False

    elem = wfapi.xml_element_root
    tags_forcelist = set(['entry'])

    try:
        panconfig = pan.config.PanConfig(config=elem,
                                         tags_forcelist=tags_forcelist)
    except pan.config.PanConfigError as msg:
        print('pan.config.PanConfigError:' + str(msg), file=sys.stderr)
        return False

    return panconfig.python()
    
def save_logfile(logfilename, fields, results):
    print("Logfile:", logfilename)
    with open(logfilename, 'w') as outputfile:
        filewriter = csv.DictWriter(outputfile, fields)
        filewriter.writeheader()
        for key,val in results.items():
            row = {fields[0] : key} # fields[0] is expected to be the dictionary key
            row.update(val)
            filewriter.writerow(row)    

def parse_options():
    options = {
        'api-key': None,
        'submit-files': None,
        'verdicts-hashfile': None,
        'verdicts-submitlog': None,
        'reports-hashfile': None,
        'reports-submitlog': None,
        'reports-dest': None,
        'timeout': None,
        }

    long_options = ['version', 'examples', 'help',
                    'api-key=', 
                    'submit-files=', 
                    'verdicts-hashfile=', 'verdicts-submitlog=', 
                    'reports-hashfile=', 'reports-submitlog=', 'reports-dest=',
                    'timeout='
                    ]

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   '',
                                   long_options)
    except getopt.GetoptError as error:
        print('getopt.GetoptError: ' + str(error), file=sys.stderr)
        sys.exit(1)

    for opt, arg in opts:
        if False:
            pass
        elif opt == '--api-key':
            options['api-key'] = arg
        elif opt == '--submit-files':
            options['submit-files'] = arg
        elif opt == '--verdicts-hashfile':
            options['verdicts-hashfile'] = arg
        elif opt == '--verdicts-submitlog':
            options['verdicts-submitlog'] = arg
        elif opt == '--reports-hashfile':
            options['reports-hashfile'] = arg
        elif opt == '--reports-submitlog':
            options['reports-submitlog'] = arg
        elif opt == '--timeout':
            options['timeout'] = arg
        elif opt == '--version':
            print('pan-python', pan.wfapi.__version__)
            sys.exit(0)
        elif opt == '--examples':
            examples()
            sys.exit(0)
        elif opt == '--help':
            usage()
            sys.exit(0)
        else:
            assert False, 'unhandled option %s' % opt

    return options

def examples():
    examples = '''Parameter examples:
    --api-key <key> --submit-files ./working_folder/malware
    --api-key <key> --verdicts-hashfile ./working_folder/hashfile.csv
    --api-key <key> --verdicts-submitlog ./working_folder/malware/WildFireSubmissionsLogfile-YYYYMMDD-HHMMSS.csv
    --api-key <key> --reports-hashfile ./working_folder/hashfile.csv
    --api-key <key> --reports-submitlog ./working_folder/WildFireVerdictsLogfile-YYYYMMDD-HHMMSS.csv
'''
    print(examples)

def usage():
    usage = '''%s [options]
    --api-key <key>               WildFire API key
    --submit-files <path>         submit all files in <path> to WildFire for analysis
    --verdicts-hashfile <file>    query WildFire verdicts for each SHA256 hash 
                                  in <file> (one hash per line)
    --verdicts-submitlog <file>   query WildFire verdicts for each SHA256 hash
                                  in the <file> logfile output from --submit-files 
    --reports-hashfile <file>     download the WildFire report for each SHA256 hash
                                  in <file> (one hash per line)
    --reports-submitlog <file>    download the WildFire reports for each SHA256 hash
                                  in the <file> logfile output from --submit-files
    --timeout <seconds>           urlopen() timeout
    --version                     display pan-python version
    --examples                    display examples of parameter usage
    --help                        display this message
'''
    print(usage % Path(__file__).name)
    
if __name__ == '__main__':
    main()
