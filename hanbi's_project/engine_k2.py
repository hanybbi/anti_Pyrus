import os
import sys
from optparse import OptionParser
import k2engine
from elasticsearch import two
from datetime import datetime, timezone
import socket

KAV_VERSION = '1'
KAV_BUILDDATE = 'Nov 30 2022'
KAV_LASTYEAR = KAV_BUILDDATE[len(KAV_BUILDDATE)-4:]

def print_k2logo() :
    print('----------------------------------------------------------------------------------')

class OptionParsingError(RuntimeError) :
    def __init__(self, msg) :
        self.msg = msg

class OptionParsingExit(Exception) :
    def __init__(self, status, msg) :
        self.msg = msg
        self.status = status

class ModifiedOptionParser(OptionParser) :
    def error(self, msg) :
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None) :
        raise OptionParsingExit(status, msg)

def define_options() :
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files", action="store_true", dest="opt_files", default=True)
    parser.add_option("-I", "--list", action="store_true", dest="opt_list", default=False)
    parser.add_option("-V", "--vlist", action="store_true", dest="opt_vlist", default=False)
    parser.add_option("-?", "--help", action="store_true", dest="opt_help", default=False)

    return parser

def parser_options() :
    parser = define_options()

    if len(sys.argv) < 2 :
        return 'NONE_OPTION', None
    else :
        try :
            (options, args) = parser.parse_args()
            if len(args) == 0 :
                return options, None
        except OptionParsingError as e :
            return 'ILLEGAL_OPTION', e.msg
        except OptionParsingExit as e :
            return 'ILLEGAL_OPTION', e.msg

        return options, args

def print_usage() :
    print('\nUsage: k2.py path[s] [options]')

def print_options() :
    options_string = \
                   '''Options:
                            -f,  --files           scan files *
                            -I,  --list            display all files
                            -V,  --vlist           display virus list
                            -?,  --help            this help
                                                   *= default option'''
    print (options_string)

def listvirus_callback(plugin_name, vnames) :
    for vname in vnames :
        print(vname, '[', plugin_name, '.kmd ]')

def convert_display_filename(real_filename) :
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    display_filename = real_filename.encode(sys.stdout.encoding, 'replace')
    return display_filename

def display_line(filename, message) :
    filename += ''
    filename = convert_display_filename(filename)
        
    print(filename)
    print(message)

def scan_callback(ret_value) :
    real_name = ret_value['filename']

    disp_name = real_name
    vname = ret_value['virus_name']

    if ret_value['result'] :
        state = 'infected'
        message = state + vname

    else :
        message = 'ok'

    elastic_log(real_name, vname)
    display_line(disp_name, message)

def elastic_log(real_name, vname) :
    current_time = datetime.now(timezone.utc)
    current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    now_file = os.path.split(real_name)[-1]
    ex_ip = socket.gethostbyname(socket.getfqdn())
    pcname = socket.gethostname()
    usr_list = {'DESKTOP-EF2BM5I' : 'user1', 'DESKTOP-3P32NCE' : 'user2', }
    usrname = 'user4'
    if pcname in usr_list :
        usrname = usr_list[pcname]
    field = 'virus'
    if vname == '':
        field = 'non-virus'
        
    log = {
    "detection time" : current_time,
    "field" : field,
    "file" : now_file,
    "file path" : real_name,
    "hostname" : "antipyrus",
    "ip" : ex_ip,
    "pc" : pcname,
    "username" : usrname,
    "virus detection" : vname}

    two.vaccine_anti(log)

def print_result(result) :
    print('Results:\n')
    print('Folders          :', result['Folders'], '\n')
    print('Files            :', result['Files'], '\n')
    print('Infected files   :', result['Infected_files'], '\n')
    print('Identified virus :', result['Identified_viruses'], '\n')
    print('I/O errors       :', result['IO_errors'], '\n')

def main() :
    options, args = parser_options()
    
    print_k2logo()

    if options == 'NONE_OPTION' :
        print_usage()
        print_options()
        return 0
    elif options == 'ILLEGAL_OPTION' :
        print_usage()
        print('Error: args')
        return 0

    if options.opt_help :
        print_usage()
        print_options()
        return 0

    k2 = k2engine.Engine()
    if not k2.set_plugins('plugins') :
        print('Error : Anti-Virus Engine set_plugins')
        return 0

    kav = k2.create_instance()
    if not kav :
        print('Error : Anti-Virus Engine create_instance')
        return 0

    if not kav.init() :
        print('Error : Anti-Virus Engine init')
        return 0

    print('Signature number: ', kav.get_signum())
    print('\n\n')

    kav.set_options(options)

    if options.opt_vlist is True :
        kav.listvirus(listvirus_callback)

    else :
        if args :
            kav.set_result()
            
            for scan_path in args :
                scan_path = os.path.abspath(scan_path)

                if os.path.exists(scan_path) :
                    kav.scan(scan_path, scan_callback)
                else :
                    print('Error : Invalid path: \'', scan_path, '\'')

            ret = kav.get_result()
            print_result(ret)
            
    kav.uninit()

if __name__ == '__main__' :
    main()