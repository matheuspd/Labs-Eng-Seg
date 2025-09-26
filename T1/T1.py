#!/usr/bin/env python3

"""
Scanner de portas TCP/UDP com banner grabbing.
Autores:
    Matheus Pereira Dias - 11207752
    Fernando Cirilo Zanchetta - 12547419
"""

import socket
import argparse
import concurrent.futures
import errno


def carregar_services():
    """
    Carrega nomes de serviços a partir do arquivo /etc/services.

    Retorna:
        dict: Mapeia (porta, protocolo) => nome do serviço
    """
    services = {}
    try:
        with open("/etc/services", "r") as f:
            for linha in f:
                if linha.startswith("#") or not linha.strip():
                    continue
                partes = linha.split()
                if len(partes) >= 2:
                    nome = partes[0]
                    porta_proto = partes[1]
                    if "/" in porta_proto:
                        porta, proto = porta_proto.split("/")
                        try:
                            services[(int(porta), proto)] = nome
                        except ValueError:
                            continue
        return services
    except FileNotFoundError:
        print("Aviso: /etc/services não encontrado. Nomes de serviços indisponíveis.")
        return {}


def banner_grab(ip, porta, servico="desconhecido"):
    """
    Tenta obter o banner (primeira resposta) de um serviço em determinada porta.

    Args:
        ip (str): IP do alvo.
        porta (int): Porta do serviço.
        servico (str): Nome do serviço, usado para enviar comandos específicos.

    Retorna:
        str ou None: Banner obtido ou None se não conseguiu.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, porta))

            # Envia comandos diferentes conforme serviço conhecido
            if servico in ["http", "https"]:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif servico == "smtp":
                sock.sendall(b"EHLO scanner\r\n")
            elif servico == "pop3":
                sock.sendall(b"QUIT\r\n")
            elif servico == "ftp":
                sock.sendall(b"USER anonymous\r\n")
            else:
                sock.sendall(b"test\r\n")

            resposta = sock.recv(1024)
            return resposta.decode(errors="ignore").strip()

    except Exception:
        return None


def scan_tcp(ip, porta, services, timeout):
    """
    Verifica se uma porta TCP está aberta usando connect_ex().

    Args:
        ip (str): IP do alvo.
        porta (int): Porta TCP.
        services (dict): Dicionário de serviços carregado de /etc/services.
        timeout (float): Timeout em segundos.

    Retorna:
        tuple: (porta, protocolo, estado, serviço, banner/versão)
    """
    servico = services.get((porta, "tcp"), "desconhecido")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
        cliente.settimeout(timeout)
        codigo = cliente.connect_ex((ip, porta))

    if codigo == 0:  # Porta aberta
        banner = banner_grab(ip, porta, servico)
        versao = banner.splitlines()[0] if banner else "?"
        return (porta, "tcp", "open", servico, versao)
    else:
        return (porta, "tcp", "closed", servico, "")


def scan_udp(ip, porta, services, timeout):
    """
    Verifica se uma porta UDP está aberta ou filtrada.

    Args:
        ip (str): IP do alvo.
        porta (int): Porta UDP.
        services (dict): Dicionário de serviços.
        timeout (float): Timeout em segundos.

    Retorna:
        tuple: (porta, protocolo, estado, serviço, info)
    """
    servico = services.get((porta, "udp"), "desconhecido")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cliente:
        cliente.settimeout(timeout)
        try:
            cliente.sendto(b"test\r\n", (ip, porta))
            data, _ = cliente.recvfrom(1024)
            return (porta, "udp", "open", servico, data[:30].decode(errors="ignore"))
        except socket.timeout:
            # Sem resposta: pode estar aberto ou filtrado
            return (porta, "udp", "open|filtered", servico, "")
        except socket.error as e:
            # Conexão recusada
            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                return (porta, "udp", "closed", servico, "")
            else:
                return (porta, "udp", f"error({getattr(e, 'errno', 0)})", servico, "")


def imprimir_resultados(resultados):
    """
    Exibe os resultados formatados em tabela.

    Args:
        resultados (list): Lista de tuplas (porta, proto, estado, servico, info)
    """
    print("\nPORT/PROTO      STATE           SERVICE         INFO")
    print("-" * 65)
    for porta, proto, estado, servico, info in resultados:
        # Mostra apenas abertos ou serviços conhecidos
        # Adicionar "open|filtered" para visualizar todas as portas UDP
        if (proto == "udp" and estado == "closed") or (estado in ["open"]) or (servico != "desconhecido"):
            port_proto = f"{porta}/{proto}"
            info_str = info if info else ""
            print(f"{port_proto:<16}{estado:<16}{servico:<16}{info_str}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Port scanner em Python - Mostra portas TCP/UDP abertas e serviços conhecidos."
    )
    parser.add_argument("ip", help="IP ou hostname do alvo")
    parser.add_argument("-p", "--portas", help="Intervalo de portas (ex: 20-100)", default="20-1024")
    parser.add_argument("--udp", help="Habilitar scan UDP", action="store_true")
    parser.add_argument("--timeout", type=float, default=0.3, help="Timeout em segundos (default=0.3)")
    parser.add_argument("--threads", type=int, default=100, help="Número máximo de threads (default=100)")
    args = parser.parse_args()

    # Resolve o hostname para IP
    try:
        ip = socket.gethostbyname(args.ip)
    except socket.gaierror:
        print(f"Erro: não foi possível resolver o host {args.ip}")
        exit(1)

    # Intervalo de portas
    try:
        inicio, fim = map(int, args.portas.split("-"))
        portas = range(inicio, fim + 1)
    except ValueError:
        print("Erro: formato inválido para intervalo de portas. Use ex: 20-100")
        exit(1)

    services = carregar_services()
    resultados = []

    # Cria pool de threads para TCP e UDP
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for porta in portas:
            futures.append(executor.submit(scan_tcp, ip, porta, services, args.timeout))
            if args.udp:
                futures.append(executor.submit(scan_udp, ip, porta, services, args.timeout))

        for future in concurrent.futures.as_completed(futures):
            resultados.append(future.result())

    # Ordena resultados por protocolo e porta
    resultados.sort(key=lambda x: (x[1], x[0]))

    imprimir_resultados(resultados)
