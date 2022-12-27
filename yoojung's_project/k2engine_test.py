import k2engine

def listvirus_callback(plugin_name, vnames) :
    for vname in vnames :
        print(vname, '     [', plugin_name, '.kmd ]')    

k2 = k2engine.Engine(debug=True)
if k2.set_plugins('plugins') :
    kav = k2.create_instance()
    if kav :
        print('[*] Success : create_instance')
        
        ret = kav.init()
        info = kav.getinfo()

        vlist = kav.listvirus(listvirus_callback)

        print('[*] Used Callback     : ', len(vlist))

        vlist = kav.listvirus()
        print('[*] Not used Callback : ', len(vlist))

        ret, vname, mid, eid = kav.scan('eicar_ex.txt')
        if ret :
            kav.disinfect('', mid, eid)
        
        kav.uninit()
