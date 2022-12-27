import os
import io
import aestest
import eicarmodule
import types
import mmap
import glob

class Engine :
    def __init__(self, debug=False) :
        self.debug = debug

        self.plugins_path = None
        self.kmdfiles = ['eicar.kmd']
        self.kmd_modules = []
        

    def set_plugins(self, plugins_path) :
        self.plugins_path = plugins_path

        if self.debug :
            print('[*] eicar.kmd')
            print('  ', self.kmdfiles)

        for kmd_name in self.kmdfiles :
            kmd_path = plugins_path + os.sep + kmd_name
            module = eicarmodule.load(kmd_name.split('.')[0])
            if module :
                self.kmd_modules.append(module)

        if self.debug :
            print('[*] kmd_modules:')
            print('  ', self.kmd_modules)

        return True

    def create_instance(self) :
        ei = EngineInstance(self.plugins_path, self.debug)
        if ei.create(self.kmd_modules) :
            return ei

        else :
            return None

class EngineInstance :
    def __init__(self, plugins_path, debug=False) :
        self.debug = debug
        self.plugins_path = plugins_path

        self.options = {}
        self.set_options()
        
        self.main_inst = []

        self.result = {}
        self.identified_virus = set()

    def create(self, kmd_modules) :
        for mod in kmd_modules :
            try :
                t = mod.Main()
                self.main_inst.append(t)
            except AttributeError :
                continue

        if len(self.main_inst) :
            if self.debug :
                print('[*] Count of Main :', len(self.main_inst))
            return True

        else :
            return False

    def init(self) :
        t_main_inst = []

        if self.debug :
            print('[*] Main_init() : ')

        for inst in self.main_inst :
            try :
                ret = inst.init(self.plugins_path)
                if not ret :
                    t_main_inst.append(inst)

                    if self.debug :
                        print('     [-] ', inst.__module__, '.init() : ', ret)
            except AttributeError :
                continue

        self.main_inst = t_main_inst

        if len(self.main_inst) :
            if self.debug :
                print('[*] Count of Main.init() :', len(self.main_inst))
            return True

        else :
            return False

    def uninit(self) :
        if self.debug :
            print('[*] Main.uninit() :')

        for inst in self.main_inst :
            try :
                ret = inst.uninit()
                if self.debug :
                    print('     [-]', inst.__module__, '.uninit() : ', ret)
            except AttributeError :
                continue

    def getinfo(self) :
        ginfo = []

        if self.debug :
            print('[*] Main.getinfo() :')

        for inst in self.main_inst :
            try :
                ret = inst.getinfo()
                ginfo.append(ret)

                if self.debug :
                    print('     [-] ', inst.__module__, '.getinfo() :')
                    for key in ret.keys() :
                        print('          - ', key, ' : ', ret[key])
            except AttributeError :
                continue

        return ginfo

    def listvirus(self, *callback) :
        vlist = []

        argc = len(callback)

        if argc == 0 :
            cb_fn = None
        elif argc ==1 :
            cb_fn = callback[0]
        else :
            return []

        if self.debug :
            print('[*] Main.listvirus() :')

        for inst in self.main_inst :
            try :
                ret = inst.listvirus()

                if isinstance(cb_fn, types.FunctionType) :
                    cb_fn(inst.__module__, ret)
                else :
                    vlist += ret

                if self.debug :
                    print('     [-] ', inst.__module__, '.listvirus() : ')
                    for vname in ret :
                        print('          - ', vname)
            except AttributeError :
                continue

        return vlist

    def __scan_file(self, filename) :
        if self.debug :
            print('[*] Main.__scan_file() :')

        try :
            ret = False
            vname = ''
            mid = -1
            eid = -1

            fp = open(filename, 'rb')
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i, inst in enumerate(self.main_inst) :
                try :
                    ret, vname, mid = inst.scan(mm, filename)
                    if ret :
                        eid = i

                        if self.debug :
                            print('     [-] ', inst.__module__, '.__scan_file() : ', vname)

                        break
                except AttributeError :
                    continue

            if mm :
                mm.close()
            if fp :
                fp.close()

            return ret, vname, mid, eid
        except IOError :
            self.result['IO_errors'] += 1

        return False, '', -1, -1

    def scan(self, filename, *callback) :
        cb_fn = None

        ret_value = {
            'filename' : '',
            'result' : False,
            'virus_name' : '',
            'virus_id' : -1,
            'engine_id' : -1
            }

        argc = len(callback)

        if argc == 1 :
            cb_fn = callback[0]
        elif argc > 1 :
            return -1

        file_scan_list = [filename]

        while len(file_scan_list) :
            try :
                real_name = file_scan_list.pop(0)

                if os.path.isdir(real_name) :
                    if real_name[-1] == os.sep :
                        real_name = real_name[:-1]

                    ret_value['result'] = False
                    ret_value['filename'] = real_name

                    self.result['Folders'] += 1

                    if self.options['opt_list'] :
                        if isinstance(cb_fn, types.FunctionType) :
                            cb_fn(ret_value)

                    flist = glob.glob(real_name + os.sep + '*')
                    file_scan_list = flist + file_scan_list

                elif os.path.isfile(real_name) :
                    ret, vname, mid, eid = self.__scan_file(real_name)

                    if ret :
                        self.result['Infected_files'] += 1
                        self.identified_virus.update([vname])

                    self.result['Files'] += 1

                    ret_value['result'] = ret
                    ret_value['engine_id'] = eid
                    ret_value['virus_name'] = vname
                    ret_value['virus_id'] = mid
                    ret_value['filename'] = real_name

                    if self.options['opt_list'] :
                        if isinstance(cb_fn, types.FunctionType) :
                            cb_fn(ret_value)
                    else :
                        if ret_value['result'] :
                            if isinstance(cb_fn, types.FunctionType) :
                                cb_fn(ret_value)
            except KeyboardInterrupt :
                return 1

        return 0
        

    def disinfect(self, filename, malware_id, engine_id) :
        ret = False

        if self.debug :
            print('[*] Main.disinfect() :')

        try :
            inst = self.main_inst[engine_id]
            ret = inst.disinfect(filename, malware_id)

            if self.debug :
                print('     [-] ', inst.__module__, '.disinfect() : ', ret)
        except AttributeError :
            pass

        return ret

    def get_signum(self) :
        signum = 0

        for inst in self.main_inst :
            try :
                ret = inst.getinfo()

                if 'sig_num' in ret :
                    signum += ret['sig_num']
            except AttributeError :
                continue

        return signum

    def set_options(self, options=None) :
        if options :
            self.options['opt_list'] = options.opt_list
        else :
            self.options['opt_list'] = False
        return True

    def set_result(self) :
        self.result['Folders'] = 0
        self.result['Files'] = 0
        self.result['Infected_files'] = 0
        self.result['Identified_viruses'] = 0
        self.result['IO_errors'] = 0

    def get_result(self) :
        self.result['Identified_virus'] = len(self.identified_virus)
        return self.result
