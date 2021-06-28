/*
Author: Helvio Junior (M4v3r1ck)

This is a stand-alone script for bypassing SSL pinning on Android apps written using Xamarin.
I don't know if it works with IOS, let me know.

 $ adb push SSLBypass.dll /data/local/tmp/ 
 $ frida -U -f com.app.mobile -l xamarin-sslbypass.js --no-pause

Inspiration:
- https://www.gosecure.net/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/
- https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/

Mono embedding doc:
http://docs.go-mono.com/?link=root%3a%2fembed

Thanks freehuntx for his work which is embedded in this script:
https://github.com/freehuntx/frida-mono-api
https://github.com/freehuntx/frida-ex-nativefunction
*/


Java.perform(function() {

    //Proxy Address
    const proxy_addr = "http://192.168.5.158:8080";
    const dll_path = "/data/local/tmp/SSLBypass.dll";
    const DEBUG = false

    const String = Java.use('java.lang.String');
    const Class = Java.use('java.lang.Class');
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
    const SystemLoad = System.load.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    function load(libPath){
        var methods = System.class.getDeclaredMethods();
        var load = undefined;
        for(var i = 0; i < methods.length; i++){
            if (methods[i].getName() == 'load'){
                //console.log(methods[i].getName());
                load = methods[i];
            }
        }
        load.invoke(null, [libPath])
    }

    SystemLoad.implementation = function(library) {
        console.log("Loading dynamic library from full path => " + library);
        return SystemLoad.call(this, library);
    }

    //Função para aguardar os módulos mono serem carregados antes de continuar
    var awaitForCondition = function(callback) {
        var int = setInterval(function() {
            var execute = false;
            try{
                var mod1 = Process.getModuleByName("libmonosgen-2.0.so");
                var mod2 = Process.getModuleByName("libxamarin-app.so");
                var mod3 = Process.getModuleByName("libmono-native.so");
                var mod4 = Process.getModuleByName("libmonodroid.so");
                if ((mod1 != null) && (mod2 != null) && (mod3 != null) && (mod4 != null))
                    console.log('[+] All modules found!');
                    clearInterval(int);
                    execute = true;
                    
            } catch (err) {
                console.log('[-] Waiting...');
                console.log(err);
            }

            //Executa fora do try para não mascarar erros
            if (execute){
                console.log('[*] Executando callback...');
                callback();
            }

        }, 500);
    }
    awaitForCondition(start);

    function start() {
        console.log('[+] Iniciando processo de hooking...');

        let monoModule = null

        Process.enumerateModules({
            onMatch: function(module){
                //console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
            }, 
            onComplete: function(){}
        });

        Process.getModuleByName("libmonosgen-2.0.so").enumerateExports().forEach(ex => {
            if (ex.name == 'mono_thread_attach')
                monoModule = ex
        })

        if (!monoModule) throw new Error('Can\'t find Mono runtime!')

        class ExNativeFunction {
            constructor(address, retType = 'void', argTypes = [], abi = 'default') {
                const native = new NativeFunction(address, retType, argTypes, abi)

                native.address = address
                native.retType = retType
                native.argTypes = argTypes
                native.abi = abi

                native.nativeCallback = callback => {
                  return new NativeCallback(callback, retType, argTypes, abi)
                }

                native.intercept = (options = {}) => {
                  return Interceptor.attach(address, options)
                }

                native.replace = callback => {
                  return Interceptor.replace(address, native.nativeCallback(callback))
                }

                return native
            }
        }

        global.ExNativeFunction = ExNativeFunction

        let MonoApi = {
            mono_assembly_foreach: ['void', ['pointer', 'pointer']],
            mono_assembly_get_image: ['pointer', ['pointer']],
            mono_class_from_name: ['pointer', ['pointer', 'pointer', 'pointer']],
            mono_class_get_method_from_name: ['pointer', ['pointer', 'pointer', 'int']],
            mono_compile_method: ['pointer', ['pointer']],
            mono_get_root_domain: ['pointer'],
            mono_string_new: ['pointer', ['pointer', 'pointer']],
            mono_domain_get: ['pointer'],
            mono_string_to_utf8: ['pointer', ['pointer']],
            mono_thread_attach: ['pointer', ['pointer']],
            mono_array_length: ['uint32', ['pointer']],
            mono_array_addr_with_size: ['pointer', ['pointer', 'int', 'uint32']],
            // ... I've omitted a lot of mono functions which are not used in this script


            mono_assembly_load_with_partial_name: ['pointer', ['pointer', 'pointer']],
            mono_field_set_value: ['void', ['pointer', 'pointer', 'pointer']],
            mono_runtime_invoke: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
            mono_field_set_value: ['void', ['pointer', 'pointer', 'pointer']],
            mono_class_get_field_from_name: ['pointer', ['pointer', 'pointer']],
            mono_field_get_value_object: ['pointer', ['pointer', 'pointer', 'pointer']],
            mono_class_get_name: ['pointer', ['pointer']],
            mono_class_get_namespace: ['pointer', ['pointer']],
            mono_object_new: ['pointer', ['pointer', 'pointer']],
            mono_array_new: ['pointer', ['pointer', 'pointer', 'int']],
            mono_get_string_class: ['pointer'],
            mono_array_set: ['void', ['pointer', 'pointer', 'uint32', 'pointer']],
            mono_method_desc_new: ['pointer', ['pointer', 'int']],
            mono_domain_assembly_open: ['pointer', ['pointer', 'pointer']],
            mono_class_get_methods: ['pointer', ['pointer', 'pointer']],
        }

        Object.keys(MonoApi).map(exportName => {

            if (MonoApi[exportName] === null) {
                MonoApi[exportName] = () => { throw new Error('Export signature missing: ' + exportName) }
            }
            else {
                const addr = Module.findExportByName('libmonosgen-2.0.so', exportName)
                MonoApi[exportName] = !addr
                    ? () => { throw new Error('Export not found: ' + exportName) }
                    : MonoApi[exportName] = new ExNativeFunction(addr, ...MonoApi[exportName])
            }
        })

        MonoApi.mono_thread_attach(MonoApi.mono_get_root_domain()) // Make sure we are attached to mono.

        //  API HElper

        const rootDomain = MonoApi.mono_get_root_domain()
        const MonoApiHelper = {
            RuntimeInvoke: (mono_method, instance = NULL, args = NULL) => {
                const exception = NULL
                const result = MonoApi.mono_runtime_invoke(mono_method, instance, args, exception)

                if (!exception.isNull()) throw new Error('Unknown exception happened.');
                return result
              },
              ClassGetFieldFromName: (mono_class, name) => {
                return MonoApi.mono_class_get_field_from_name(mono_class, Memory.allocUtf8String(name))
              },
              FieldGetValueObject: (mono_field, mono_object, domain = rootDomain) => {
                return MonoApi.mono_field_get_value_object(domain, mono_field, mono_object)
              },
              ClassGetMethodFromName: (mono_class, name, argCnt = -1) => {
                return MonoApi.mono_class_get_method_from_name(mono_class, Memory.allocUtf8String(name), argCnt)
              },
              Intercept: (klass, methodName, callbacks) => {
                if (!callbacks) throw new Error('callbacks must be an object!');
                  if (!callbacks.onEnter && !callbacks.onLeave) throw new Error('At least one callback is required!');

                  let md = MonoApiHelper.ClassGetMethodFromName(klass, methodName);
                  if (!md) throw new Error('Method not found!');
                  let impl = MonoApi.mono_compile_method(md)

                  Interceptor.attach(impl, {...callbacks});
              },
              ClassGetName: mono_class => {
                return Memory.readUtf8String(MonoApi.mono_class_get_name(mono_class))
              },
              ObjectNew: (mono_class, domain = rootDomain) => MonoApi.mono_object_new(domain, mono_class),
              NewClass: (mono_class, params, domain = rootDomain) => {
                /* First, create the instance, boxed */
                obj = mono_object_new (domain, mono_class);

                /* Unbox on a void* variable */
                o = mono_object_unbox (obj);

                /* Call the method/constructor on the unboxed */
                mono_runtime_invoke (ctor, o, params, NULL);

                /* But ... return the MonoObject* representation */
                return obj;
              },
              MethodGetName: mono_method => Memory.readUtf8String(MonoApi.mono_method_get_name(mono_method)),
              ClassGetMethods: mono_class => {
                const methods = []
                const iter = Memory.alloc(Process.pointerSize)
                let method

                while(!(method = MonoApi.mono_class_get_methods(mono_class, iter)).isNull()) {
                  console.log(MonoApiHelper.MethodGetName(method));  
                  methods.push(method)
                }
                return methods
              }
        }
        //export default MonoApiHelper

        // =============================================================================
        // =============================================================================

        console.warn("\n\n *** XAMARIN ANTIPINNING by M4V3R1CK *** \n")

        var assemblies = []
        MonoApi.mono_assembly_foreach(new NativeCallback(x => { assemblies.push(x) }, 'void', ['pointer', 'pointer']), NULL)

        function hook(namespace, klass, method, callbacks){
            assemblies.forEach(x=>{
                var mono_img = MonoApi.mono_assembly_get_image(x)
                var mono_class = MonoApi.mono_class_from_name(mono_img,
                                                        Memory.allocUtf8String(namespace),
                                                        Memory.allocUtf8String(klass))
                if(mono_class != 0x0){
                    if(DEBUG) console.log("Found class: " + klass)
                    
                    var methods = method.split("/")
                    for(var i=0; i < methods.length; i++){
                        var mono_method = MonoApi.mono_class_get_method_from_name(mono_class, Memory.allocUtf8String(methods[i]), -1)
                        if (mono_method == 0x0){
                            if(DEBUG) console.log("*** Method \"" + methods[i] + "\" not found")
                            return
                        }
                        if(DEBUG) console.log("Method \"" + methods[i] + "\" found")
                        
                        var impl = MonoApi.mono_compile_method(mono_method)
                        Interceptor.attach(impl, {...callbacks})
                    }            
                }
            })
        }

        function get_class(namespace, klass){
            var fclass = undefined;
            assemblies.forEach(x=>{
                var mono_img = MonoApi.mono_assembly_get_image(x)
                var mono_class = MonoApi.mono_class_from_name(mono_img,
                                                        Memory.allocUtf8String(namespace),
                                                        Memory.allocUtf8String(klass))
                if(mono_class != 0x0){
                    if(DEBUG) console.log("Found2 class: " + klass)
                    
                    fclass = mono_class;  
                          
                }
            })
            return fclass;
        }


        const mono = MonoApi.module
        const domain = MonoApi.mono_domain_get()

        let injected_assembly = MonoApi.mono_domain_assembly_open(domain, Memory.allocUtf8String(dll_path));
        let injected_img = MonoApi.mono_assembly_get_image(injected_assembly);
        let injected_class= MonoApi.mono_class_from_name(injected_img,
                                                    Memory.allocUtf8String('SSLBypass'),
                                                    Memory.allocUtf8String('Bypass'));


        let injected_method = MonoApiHelper.ClassGetMethodFromName(injected_class, "GetHandler", -1);
        if (DEBUG) console.log(`[*] injected_method: ${injected_method}`);

        //Hook da função que define o proxy
        MonoApiHelper.Intercept(injected_class, 'ProxyText', {
            onLeave: (retval) => {
                //console.log(`[*] SSLBypass.Bypass.ProxyText called`);
                console.log(`[*] Setting proxy to ${proxy_addr}`);
                var proxy = MonoApi.mono_string_new(domain, Memory.allocUtf8String(proxy_addr))
                retval.replace(proxy);
            }
        });

        //Call for the first time the Funcion responsible for set Static variable with Proxy address
        let gc_instance = MonoApi.mono_object_new(domain, injected_class);
        let gc_method1 = MonoApiHelper.ClassGetMethodFromName(injected_class, "FirstCallProxy", -1);
        if (DEBUG) console.log(`[*] FirstCallProxy: ${gc_method1}`); 
        MonoApiHelper.RuntimeInvoke(gc_method1, gc_instance, NULL );
        

        // Locate System.Net.Http.dll
        let hooked = false;
        
        let status = Memory.alloc(0x1000);
        let http = MonoApi.mono_assembly_load_with_partial_name(Memory.allocUtf8String('System.Net.Http'), status);
        let img = MonoApi.mono_assembly_get_image(http);

        let kHandler = MonoApi.mono_class_from_name(img,
                                                    Memory.allocUtf8String('System.Net.Http'),
                                                    Memory.allocUtf8String('HttpClientHandler'));

        

        //let kHandler = get_class('System.Net.Http', 'HttpClientHandler');
        
        if (DEBUG) console.log(`[*] kHandler: ${kHandler}`);
        if (kHandler) {
            
          let ctor = MonoApiHelper.ClassGetMethodFromName(kHandler, 'CreateDefaultHandler');

          // Hook HttpMessageInvoker.SendAsync
          //let kInvoker = get_class('System.Net.Http', 'HttpMessageInvoker');
          let kInvoker = MonoApi.mono_class_from_name(img,
                                              Memory.allocUtf8String('System.Net.Http'),
                                              Memory.allocUtf8String('HttpMessageInvoker'));

          
          MonoApiHelper.Intercept(kInvoker, 'SendAsync', {
            onEnter: (args) => {
              if (DEBUG) console.log(`[*] HttpClientHandler.SendAsync called`);
              try {
                  let self = args[0];
                  //console.log(MonoApiHelper.ClassGetName(args[1]));
                  let handler = MonoApiHelper.ClassGetFieldFromName(kInvoker, '_handler');

                  let injected_instance = MonoApi.mono_object_new(domain, injected_class);
                  if (DEBUG) console.log(`[*] injected_instance: ${injected_instance}`);

                  let pClientHandler = MonoApiHelper.RuntimeInvoke(injected_method, injected_instance); 
                  if (DEBUG) console.log(`[*] pClientHandler: ${pClientHandler}`);

                  MonoApi.mono_field_set_value(self, handler, pClientHandler);
                  console.log(`[+]   Replaced with default handler @ ${pClientHandler}`);
             }catch(ex){
                //Nada
                console.log(`[+]   Erro ${ex}`);
             }     
            }
            
          });

          console.log('[+] Hooked HttpMessageInvoker.SendAsync');
          hooked = true;
        } else {
          console.log('[-] HttpClientHandler not found');
        }

    }

    
})


