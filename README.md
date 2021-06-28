# Xamarin SSL Unpinning

Este projeto visa realizar o Bypass de SSL Pinning no Android Xamarin

## Metodologias

Devido a arquitetura do Android Xamarin e do método utilizado para Bypass, por padrão, ao realizar o Bypass perde-se também a confoguração de proxy. Então neste procedimento temos duas metodologias de realização do SSL Unpinning:

1. Utilização de scripts frida com DLL .NET (com proxy)
2. Utilização somente de scripts frida (sem proxy)

**Nota:** Apesar de nativamente ser sem proxy vou demonstrar como utilizar o Iptables p/ realizar o proxy.


### Método 1: Utilização de scripts frida com DLL .NET

Para este método foi desenvolvido uma DLL que realiza o bypass e adicionalmente configura o proxy para que o tráfego seja encaminhado para o Burp

#### Enviando a DLL para o Android

O primeiro passo é enviar a DLL para o dispositivo android

```bash
adb push SSLBypass.dll /data/local/tmp/ 
```

#### Ajustando o script Frida

Para o correto funcionamento edite as linhas abaixo dentro do script para corresponder ao endereço IP/porta do seu Burp, bem como o caminho completo da DLL dentro do Android.

```
const proxy_addr = "http://192.168.5.158:8080";
const dll_path = "/data/local/tmp/SSLBypass.dll";
```

#### Execução Script frida

```bash
frida -U -f [app_id] -l xamarin-sslbypass_proxy.js --no-pause
```


### Método 2: Utilização somente de scripts frida

Neste método utilizaremos somente script frida para realizar o Unpinning. Porém neste método o aplicativo perde toda a configuração do proxy, sendo assim necessitaremos utilizar o ADB + Iptables para direcionar todo op tráfego HTTP e HTTPS para o burp.

#### Direcionando tráfego para o Burp

**Passo 1: Proxy invisível Burp**
Primeiro passo a ser realizado é na configuração de proxy do Burp habilitar o modo de proxy transparente. Dentro do **Burp**, vá em **Proxy** > **Options** > Selecione o listener e clique em **Edit** navege até a aba **Request handling** e selecione a opção **Support invisible proxying**.

**Passo 2: Tunnel reverso ADB**
Posteriormente crie um tunnel reverso TCP entre o seu dispotivido Android e sua maquina (onde está o Burp). Com este comando será aberto uma porta 8080 localmente dentro do dispositivo Android e todo o tráfego encaminhado para ela será direcionado para a porta 8080 da sua maquina (onde o comando foi executado).

```bash
adb reverse tcp:8080 tcp:8080
```

**Passo 3: Regras IPTABLES**
Por fim adicione as regras iptables para direcionar todo o tráfego HTTP e HTTP p/ este tunnel reverso que encaminhará para o Burp.

```bash
# Quando o ADB está modo root
adb shell iptables -t nat -A OUTPUT -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8080
adb shell iptables -t nat -A OUTPUT -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080

# Quando o ADB está em modo usuário comum (não root)
adb shell su - -c iptables -t nat -D OUTPUT -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8080
adb shell su - -c iptables -t nat -D OUTPUT -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
```

**Nota:** Os comandos acima nada se referem a estar rodando em dispositivo rootado ou não. A referencia de modo root é para quando você executa **adb shell**, se ao executar o shell spawnado é diretamente com o usuário root, então vc está com o adb em modo root, caso contrário você está com o adb em modo não root, mas tem a capacidade de executar **su -** e escalar privilégio para root.

#### Execução Script frida

```bash
frida -U -f [app_id] -l xamarin-sslbypass.js --no-pause
```


## Estudo adicional

Recomendo a leitura dos textos abaixo:

- [Arquitetura do Xamarin.Android](http://www.macoratti.net/16/07/xamand_xam1.htm)
- [Bypassing Xamarin Certificate Pinning on Android](https://www.gosecure.net/blog/2020/04/06/bypassing-xamarin-certificate-pinning-on-android/)
- [](http://docs.go-mono.com/?link=root%3a%2fembed)
- [](https://github.com/freehuntx/frida-mono-api)
- [](https://github.com/freehuntx/frida-ex-nativefunction)

