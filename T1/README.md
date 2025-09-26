# Trabalho 1 - Port Scan

Este projeto implementa um scanner de portas TCP e UDP com banner grabbing semelhante ao Nmap, mas feito em Python puro utilizando apenas a biblioteca padrão.
Ele identifica portas abertas/fechadas/filtradas, reconhece serviços conhecidos usando o arquivo /etc/services e tenta coletar banners dos serviços para exibir informações adicionais (versão/protocolo).

## Autores

- Matheus Pereira Dias
- Fernando Cirilo Zanchetta

## Funcionalidades

- Scan TCP e UDP: Verifica se portas estão abertas, fechadas ou filtradas.
- Banner grabbing: Envia comandos iniciais e captura a resposta do serviço (por exemplo, versões de HTTP, SMTP, FTP etc.).
- Reconhecimento de serviços: Usa o arquivo /etc/services para mapear portas a serviços conhecidos.
- Execução multithread: Scans rápidos usando ThreadPoolExecutor.
- Configuração flexível: Permite definir intervalo de portas, timeout, número de threads e opção de scan UDP.

Nenhuma dependência externa. O script utiliza apenas biblioteca padrão do Python 3:
`socket, argparse, concurrent.futures, errno`

### Uso

Para executar o código:

```bash
python3 T1.py [-h] [-p PORTAS] [--udp] [--timeout TIMEOUT] [--threads THREADS] ip
```

Use o comando abaixo para mais detalhes:

```bash
python3 T1.py -h
```

# Observações

- Portas UDP que não respondem aparecem como `open|filtered` (comportamento semelhante ao Nmap).
- A execução multithread aumenta a velocidade do scan, mas pode gerar falsos positivos se o timeout for muito baixo.
- Para coletar banners mais completos, aumente o timeout.

## Teste

Foi utilizado para teste a VM Metasploitable 2. Aqui está um exemplo para um scan TCP e UDP:

```bash
python3 T1.py --udp [IP-METASPLOITABLE-VM]
```

Saída:

```bash
python3 T1.py 192.168.122.10 --udp

PORT/PROTO      STATE           SERVICE         INFO
-----------------------------------------------------------------
20/tcp          closed          ftp-data
21/tcp          open            ftp             220 (vsFTPd 2.3.4)
22/tcp          open            ssh             SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
23/tcp          open            telnet          ▒ #'
25/tcp          open            smtp            220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
37/tcp          closed          time
43/tcp          closed          whois
49/tcp          closed          tacacs
53/tcp          open            domain          ?
70/tcp          closed          gopher
79/tcp          closed          finger
80/tcp          open            http            HTTP/1.1 200 OK
88/tcp          closed          kerberos
102/tcp         closed          iso-tsap
104/tcp         closed          acr-nema
106/tcp         closed          poppassd
110/tcp         closed          pop3
111/tcp         open            sunrpc          ?
113/tcp         closed          auth
119/tcp         closed          nntp
135/tcp         closed          epmap
139/tcp         open            netbios-ssn     ?
143/tcp         closed          imap2
161/tcp         closed          snmp
162/tcp         closed          snmp-trap
163/tcp         closed          cmip-man
164/tcp         closed          cmip-agent
174/tcp         closed          mailq
179/tcp         closed          bgp
199/tcp         closed          smux
209/tcp         closed          qmtp
210/tcp         closed          z3950
345/tcp         closed          pawserv
346/tcp         closed          zserv
369/tcp         closed          rpc2portmap
370/tcp         closed          codaauth2
389/tcp         closed          ldap
427/tcp         closed          svrloc
443/tcp         closed          https
444/tcp         closed          snpp
445/tcp         open            microsoft-ds    ?
464/tcp         closed          kpasswd
465/tcp         closed          submissions
487/tcp         closed          saft
512/tcp         open            exec            Where are you?
513/tcp         open            login           ?
514/tcp         open            shell           ?
515/tcp         closed          printer
538/tcp         closed          gdomap
540/tcp         closed          uucp
543/tcp         closed          klogin
544/tcp         closed          kshell
548/tcp         closed          afpovertcp
554/tcp         closed          rtsp
563/tcp         closed          nntps
587/tcp         closed          submission
607/tcp         closed          nqs
628/tcp         closed          qmqp
631/tcp         closed          ipp
636/tcp         closed          ldaps
646/tcp         closed          ldp
655/tcp         closed          tinc
706/tcp         closed          silc
749/tcp         closed          kerberos-adm
750/tcp         closed          kerberos4
751/tcp         closed          kerberos-master
754/tcp         closed          krb-prop
775/tcp         closed          moira-db
777/tcp         closed          moira-update
783/tcp         closed          spamd
853/tcp         closed          domain-s
871/tcp         closed          supfilesrv
873/tcp         closed          rsync
989/tcp         closed          ftps-data
990/tcp         closed          ftps
992/tcp         closed          telnets
993/tcp         closed          imaps
995/tcp         closed          pop3s
21/udp          open|filtered   fsp
37/udp          open|filtered   time
49/udp          open|filtered   tacacs
53/udp          open|filtered   domain
67/udp          open|filtered   bootps
68/udp          open|filtered   bootpc
69/udp          open|filtered   tftp
88/udp          open|filtered   kerberos
111/udp         open|filtered   sunrpc
123/udp         open|filtered   ntp
137/udp         open|filtered   netbios-ns
138/udp         open|filtered   netbios-dgm
161/udp         open|filtered   snmp
162/udp         open|filtered   snmp-trap
163/udp         open|filtered   cmip-man
164/udp         open|filtered   cmip-agent
177/udp         open|filtered   xdmcp
213/udp         open|filtered   ipx
319/udp         open|filtered   ptp-event
320/udp         open|filtered   ptp-general
369/udp         open|filtered   rpc2portmap
370/udp         open|filtered   codaauth2
371/udp         open|filtered   clearcase
389/udp         open|filtered   ldap
427/udp         open|filtered   svrloc
443/udp         open|filtered   https
464/udp         open|filtered   kpasswd
500/udp         open|filtered   isakmp
512/udp         open|filtered   biff
513/udp         open|filtered   who
514/udp         open|filtered   syslog
517/udp         open|filtered   talk
518/udp         open|filtered   ntalk
520/udp         open|filtered   route
538/udp         open|filtered   gdomap
546/udp         open|filtered   dhcpv6-client
547/udp         open|filtered   dhcpv6-server
554/udp         open|filtered   rtsp
623/udp         open|filtered   asf-rmcp
636/udp         open|filtered   ldaps
646/udp         open|filtered   ldp
655/udp         open|filtered   tinc
750/udp         open|filtered   kerberos4
751/udp         open|filtered   kerberos-master
752/udp         open|filtered   passwd-server
779/udp         open|filtered   moira-ureg
853/udp         open|filtered   domain-s
```
