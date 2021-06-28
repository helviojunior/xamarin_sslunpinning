using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;

using System.Net.Http;
using Android.Util;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Reflection;
using System.Collections.Generic;

namespace SSLBypass
{
    public class Bypass
    {
        string tag = "SSLBypass";
        public static string p = "";
        
        public void MakeTest1()
        {
            Log.Error(tag, "Teste 001");

            Console.WriteLine("Teste 002");

            throw new Exception("Teste 003");
        }

        public void PrintText(String text)
        {
            Console.WriteLine("SSLBypass -> PrintText");
            Console.WriteLine("SSLBypass -> Text: " + text);
        }
        
        public String ProxyText()
        {
            if (Bypass.p != "")
            {
                return Bypass.p;
            }
            else
            {
                return "";
            }
        }

        public void FirstCallProxy()
        {
            Console.WriteLine("SSLBypass -> System Proxy -> Host: " + Bypass.p);

            String proxy = this.ProxyText();

            if (proxy != "")
            {
                Bypass.p = proxy;
                Console.WriteLine("SSLBypass -> System Proxy -> Host: " + Bypass.p);
            }
        }

        public void PrintInfo()
        {

            //string host = Java.Lang.JavaSystem.GetProperty("http.proxyHost").TrimEnd('/');
            //string port = Java.Lang.JavaSystem.GetProperty("http.proxyPort");

            String proxy = this.ProxyText();

            Console.WriteLine("SSLBypass -> System Proxy -> Host: " + proxy);

            //Console.WriteLine("SSLBypass -> WebProxy Constructors");
            ListClassInfo("System.Net", "WebProxy");
            //ListWebProxyConstructor();


            ListClassInfo("System.Net.Http", "HttpClientHandler");
            ListClassInfo("Java.Lang", "JavaSystem");

        }

        /*
        public void ListWebProxyConstructor()
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;

            List<string> classlist = new List<string>();

            Assembly[] asms = currentDomain.GetAssemblies();

            foreach (Assembly asm in asms)
            {

                List<string> namespacelist = new List<string>();

                foreach (Type type in asm.GetTypes())
                {
                    if ((type.Namespace == "System.Net") && (type.Name == "WebProxy"))
                    {
                        ConstructorInfo[] ci = type.GetConstructors();
                        foreach (ConstructorInfo i in ci)
                        {
                            Console.WriteLine("SSLBypass -> System.Net.WebProxy -> " + i.ToString());
                        }
                    }
                }

            }

        }*/

        public void ListClassInfo(String ns, String className)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;

            List<string> classlist = new List<string>();

            Assembly[] asms = currentDomain.GetAssemblies();

            foreach (Assembly asm in asms)
            {

                List<string> namespacelist = new List<string>();

                foreach (Type type in asm.GetTypes())
                {
                    if ((type.Namespace == ns) && (type.Name == className))
                    {
                        Console.WriteLine("SSLBypass -> "+ ns + "."+ className +" -> Constructors");
                        ConstructorInfo[] ci = type.GetConstructors();
                        foreach (ConstructorInfo i in ci)
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> " + i.ToString());
                        }

                        Console.WriteLine("SSLBypass ->" + ns + "." + className + " Methods");
                        foreach (MethodInfo item in type.GetMethods())
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: " + item.IsPublic + ", IsPrivate: " + item.IsPrivate + ", IsStatic: " + item.IsStatic);
                        }

                        //get the private methods
                        foreach (MethodInfo item in type.GetMethods(BindingFlags.Instance | BindingFlags.NonPublic))
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: " + item.IsPublic + ", IsPrivate: " + item.IsPrivate + ", IsStatic: " + item.IsStatic);
                        }

                        //get the static methods
                        foreach (MethodInfo item in type.GetMethods(BindingFlags.Static | BindingFlags.NonPublic))
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: " + item.IsPublic + ", IsPrivate: " + item.IsPrivate + ", IsStatic: " + item.IsStatic);
                        }

                        Console.WriteLine("SSLBypass ->" + ns + "." + className + " Properties");

                        foreach (PropertyInfo item in type.GetProperties())
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: true" );
                        }

                        //get the private methods
                        foreach (PropertyInfo item in type.GetProperties(BindingFlags.Instance | BindingFlags.NonPublic))
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: false" );
                        }

                        //get the static methods
                        foreach (PropertyInfo item in type.GetProperties(BindingFlags.Static | BindingFlags.NonPublic))
                        {
                            Console.WriteLine("SSLBypass -> " + ns + "." + className + " -> Name: " + item.Name + ", IsPublic: false, IsStatic: false");
                        }

                    }
                }

            }

        }


        public List<string> _getClasses(string nameSpace)
        {
            AppDomain currentDomain = AppDomain.CurrentDomain;

            List<string> classlist = new List<string>();

            Assembly[] asms = currentDomain.GetAssemblies();

            foreach (Assembly asm in asms)
            {

                List<string> namespacelist = new List<string>();
                

                foreach (Type type in asm.GetTypes())
                {
                    if (type.Namespace == nameSpace)
                        namespacelist.Add(type.Name);
                }

                foreach (string classname in namespacelist)
                    classlist.Add(classname);
            }

            return classlist;
        }

        public Object GetHandler()
        {
            Console.WriteLine("SSLBypass -> " + "GetHandler");

            String proxy = this.ProxyText();
            Console.WriteLine("SSLBypass -> System Proxy -> Host: " + proxy);

            HttpClientHandler h = new HttpClientHandler();

            var hander = h.GetType().GetMethod("CreateDefaultHandler", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, null);

            if (proxy != "" && proxy != null)
            {
                WebProxy tst = null;
                try
                {
                    String[] bypassList = new String[] { };

                    tst = new WebProxy(new Uri(proxy), false, bypassList, null);
                    Console.WriteLine("SSLBypass -> " + tst.ToString());

                    if (hander is null)
                    {
                        Console.WriteLine("SSLBypass -> _delegatingHandler is null");
                    }
                    else
                    {
                        //Console.WriteLine("SSLBypass -> _delegatingHandler is not null");

                        FieldInfo fieldSettings = hander.GetType().GetField("_settings", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                        var _settings = fieldSettings.GetValue(hander);
                        
                        if (hander is null)
                        {
                            Console.WriteLine("SSLBypass -> _settings is null");
                        }
                        else
                        {
                           // Console.WriteLine("SSLBypass -> _settings is not null");
                            Type hType = _settings.GetType();

                           //Console.WriteLine("SSLBypass -> Type: " + hType.ToString());

                            MethodInfo mClone = hType.GetMethod("Clone");
                            var newSettings = mClone.Invoke(_settings, null);

                            //Console.WriteLine("SSLBypass -> Clonned? " + (newSettings is null ? false : true).ToString());

                            FieldInfo fieldProxy = hType.GetField("_proxy", BindingFlags.Instance | BindingFlags.NonPublic);
                            fieldProxy.SetValue(newSettings, tst);

                            FieldInfo fieldUseProxy = hType.GetField("_useProxy", BindingFlags.Instance | BindingFlags.NonPublic);
                            fieldUseProxy.SetValue(newSettings, true);


                            fieldSettings.SetValue(hander, newSettings);

                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("SSLBypass -> " + ex.Message + ex.StackTrace);
                }
            }

            return hander;
        }

    }
}