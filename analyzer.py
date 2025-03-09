import scapy.all as scapy
from scapy.layers import http
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import time
import os
import datetime
import argparse
import sys
import socket
import ipaddress
import subprocess
import platform
import threading
import json
import random
import psutil  # Asegúrate de instalar: pip install psutil

class AnalizadorTrafico:
    def __init__(self):
        self.paquetes_capturados = []
        self.conexiones = defaultdict(int)
        self.puertos_destino = Counter()
        self.ips_destino = Counter()
        self.protocolos = Counter()
        self.dominios_dns = Counter()
        self.conexiones_activas = []
        self.fecha_inicio = datetime.datetime.now()
        
    def cargar_pcap(self, archivo_pcap):
        """
        Carga paquetes desde un archivo PCAP.
        
        Args:
            archivo_pcap: Ruta al archivo PCAP
        """
        if not os.path.exists(archivo_pcap):
            print(f"Error: El archivo {archivo_pcap} no existe.")
            return False
            
        print(f"Cargando paquetes desde archivo: {archivo_pcap}...")
        
        try:
            # Cargar paquetes desde el archivo PCAP
            self.paquetes_capturados = scapy.rdpcap(archivo_pcap)
            
            print(f"Carga completada. Se cargaron {len(self.paquetes_capturados)} paquetes.")
            self.analizar_paquetes()
            return True
        except Exception as e:
            print(f"Error al cargar el archivo PCAP: {e}")
            return False
    
    def obtener_conexiones_sin_privilegios(self):
        """
        Obtiene las conexiones de red activas usando psutil,
        sin necesidad de permisos de administrador.
        """
        print("Obteniendo conexiones de red activas...")
        self.conexiones_activas = []
        
        try:
            # Usar psutil para obtener las conexiones activas (no requiere privilegios)
            conexiones_obtenidas = psutil.net_connections(kind='all')
            
            print(f"Se obtuvieron {len(conexiones_obtenidas)} conexiones activas.")
            
            # Procesar las conexiones para adaptarlas a nuestro formato
            for conn in conexiones_obtenidas:
                # Omitir conexiones sin información remota
                if not conn.raddr:
                    continue
                    
                # Extraer información relevante
                if len(conn.raddr) >= 2:
                    src_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
                    src_port = conn.laddr.port if conn.laddr else 0
                    dst_ip = conn.raddr.ip
                    dst_port = conn.raddr.port
                    protocolo = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    estado = conn.status if hasattr(conn, 'status') else "UNKNOWN"
                    
                    # Agregar a nuestra lista de conexiones activas
                    self.conexiones_activas.append({
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocolo": protocolo,
                        "estado": estado,
                        "pid": conn.pid
                    })
                    
                    # Actualizar contadores y estadísticas
                    self.ips_destino[dst_ip] += 1
                    self.puertos_destino[dst_port] += 1
                    self.protocolos[protocolo] += 1
                    
                    # Registrar conexión en el formato que espera el resto del código
                    conexion_key = (src_ip, dst_ip, dst_port, protocolo)
                    self.conexiones[conexion_key] += 1
            
            return True
        except Exception as e:
            print(f"Error al obtener conexiones: {e}")
            return False
    
    def realizar_escaneo_basico_puertos(self, host='127.0.0.1', puertos_comunes=[80, 443, 8080, 22, 21]):
        """
        Realiza un escaneo básico de puertos usando sockets, sin necesidad de permisos elevados.
        Solo funciona para algunos puertos en el host local o hosts remotos específicos.
        """
        print(f"Realizando escaneo básico de puertos en {host}...")
        resultados = []
        
        for puerto in puertos_comunes:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            resultado = sock.connect_ex((host, puerto))
            if resultado == 0:
                print(f"Puerto {puerto} abierto en {host}")
                
                # Registrar la información del puerto
                self.puertos_destino[puerto] += 1
                self.ips_destino[host] += 1
                self.protocolos["TCP"] += 1
                
                # Agregar a conexiones
                conexion_key = ('127.0.0.1', host, puerto, "TCP")
                self.conexiones[conexion_key] += 1
                
                # Registrar para resultados
                resultados.append((host, puerto, "TCP", "OPEN"))
            sock.close()
            
        print(f"Escaneo completado. Se encontraron {len(resultados)} puertos abiertos.")
        return resultados
    
    def obtener_informacion_dns(self, dominios=['google.com', 'github.com', 'facebook.com']):
        """
        Obtiene información DNS básica para los dominios especificados,
        sin necesidad de privilegios especiales.
        """
        print("Obteniendo información DNS...")
        
        for dominio in dominios:
            try:
                ip = socket.gethostbyname(dominio)
                print(f"Resolución DNS: {dominio} -> {ip}")
                
                # Actualizar contadores
                self.dominios_dns[dominio] += 1
                self.ips_destino[ip] += 1
                self.protocolos["DNS"] += 1
                
                # Agregar a conexiones
                conexion_key = ('127.0.0.1', ip, 53, "UDP")
                self.conexiones[conexion_key] += 1
                
            except Exception as e:
                print(f"Error al resolver {dominio}: {e}")
                
    def resolver_ips_a_nombres(self):
        """Intenta resolver direcciones IP a nombres de host"""
        ips_resueltas = {}
        
        for ip in self.ips_destino:
            try:
                nombre = socket.gethostbyaddr(ip)[0]
                ips_resueltas[ip] = nombre
            except:
                ips_resueltas[ip] = ip
                
        return ips_resueltas
        
    def analizar_conexiones_activas(self):
        """
        Analiza las conexiones activas obtenidas mediante métodos sin privilegios
        y genera estadísticas similares a las que produciría el análisis de paquetes.
        """
        if not self.conexiones_activas and not self.conexiones:
            print("No hay conexiones para analizar. Ejecute una captura primero.")
            return False
            
        # Procesamiento ya realizado en obtener_conexiones_sin_privilegios()
        return True
    
    def analizar_paquetes(self):
        """Analiza los paquetes capturados y genera estadísticas"""
        for paquete in self.paquetes_capturados:
            # Analizar capa IP
            if paquete.haslayer(scapy.IP):
                # Contar IPs de destino
                ip_dst = paquete[scapy.IP].dst
                self.ips_destino[ip_dst] += 1
                
                # Identificar protocolo
                if paquete.haslayer(scapy.TCP):
                    self.protocolos["TCP"] += 1
                    # Extraer puertos
                    puerto_dst = paquete[scapy.TCP].dport
                    self.puertos_destino[puerto_dst] += 1
                    # Registrar conexión
                    conexion = (paquete[scapy.IP].src, paquete[scapy.IP].dst, puerto_dst, "TCP")
                    self.conexiones[conexion] += 1
                    
                elif paquete.haslayer(scapy.UDP):
                    self.protocolos["UDP"] += 1
                    puerto_dst = paquete[scapy.UDP].dport
                    self.puertos_destino[puerto_dst] += 1
                    conexion = (paquete[scapy.IP].src, paquete[scapy.IP].dst, puerto_dst, "UDP")
                    self.conexiones[conexion] += 1
                    
                # Detectar consultas DNS
                if paquete.haslayer(scapy.DNSQR):
                    nombre_dominio = paquete[scapy.DNSQR].qname.decode('utf-8', errors='ignore')
                    self.dominios_dns[nombre_dominio] += 1
                    
                # Más protocolos
                if paquete.haslayer(scapy.ICMP):
                    self.protocolos["ICMP"] += 1
                elif paquete.haslayer(http.HTTPRequest):
                    self.protocolos["HTTP"] += 1
    
    def generar_datos_simulados(self, cantidad=100):
        """
        Genera datos de red simulados para demostración.
        Útil cuando no se tienen permisos para capturar tráfico real.
        """
        print(f"Generando {cantidad} conexiones simuladas para demostración...")
        
        # Protocolos comunes
        protocolos = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP"]
        
        # Puertos comunes
        puertos_comunes = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        
        # IPs locales y conocidas
        ips = ["192.168.1.1", "192.168.1.100", "192.168.1.254", 
               "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
               "172.217.170.78", "31.13.72.36", "140.82.121.3"]
               
        # Dominios comunes
        dominios = ["google.com", "facebook.com", "github.com", "microsoft.com", 
                    "amazon.com", "twitter.com", "linkedin.com", "example.com"]
        
        # Generar conexiones aleatorias
        for _ in range(cantidad):
            # Seleccionar valores aleatorios
            protocolo = random.choice(protocolos)
            puerto = random.choice(puertos_comunes)
            ip_src = "192.168.1." + str(random.randint(2, 99))
            ip_dst = random.choice(ips)
            
            # Actualizar contadores
            self.protocolos[protocolo] += 1
            self.puertos_destino[puerto] += 1
            self.ips_destino[ip_dst] += 1
            
            # Registrar conexión
            conexion = (ip_src, ip_dst, puerto, protocolo)
            self.conexiones[conexion] += 1
            
            # Agregar algunos dominios DNS aleatorios
            if random.random() < 0.3:  # 30% de probabilidad
                dominio = random.choice(dominios)
                self.dominios_dns[dominio] += 1
                
        print(f"Generación de datos simulados completada.")
        return True
    
    def detectar_anomalias(self):
        """Detecta posibles anomalías en el tráfico capturado"""
        anomalias = []
        
        # Conexiones a puertos inusuales
        puertos_comunes = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080}
        for conexion, cantidad in self.conexiones.items():
            _, ip_dst, puerto, protocolo = conexion
            if puerto not in puertos_comunes and puerto < 1024:
                anomalias.append(
                    f"Conexión inusual a puerto privilegiado: {ip_dst}:{puerto} ({protocolo}) - {cantidad} paquetes/conexiones"
                )
        
        # Detección de muchas conexiones al mismo destino
        umbral_conexiones = 20
        for ip, count in self.ips_destino.items():
            if count > umbral_conexiones:
                anomalias.append(f"Alto volumen de tráfico hacia {ip}: {count} paquetes/conexiones")
        
        return anomalias
            
    def generar_informe(self):
        """Genera un informe del análisis de tráfico"""
        if not self.paquetes_capturados and not self.conexiones:
            print("No hay datos para analizar. Capture o cargue paquetes primero, o use las opciones sin privilegios.")
            return
            
        print("\n" + "="*50)
        print("INFORME DE ANÁLISIS DE TRÁFICO DE RED")
        print("="*50)
        print(f"Fecha y hora: {datetime.datetime.now()}")
        print(f"Inicio de captura/análisis: {self.fecha_inicio}")
        
        if self.paquetes_capturados:
            print(f"Total de paquetes analizados: {len(self.paquetes_capturados)}")
        else:
            print(f"Total de conexiones analizadas: {len(self.conexiones)}")
        
        print("\nDISTRIBUCIÓN DE PROTOCOLOS:")
        for protocolo, cantidad in self.protocolos.most_common(10):
            print(f"- {protocolo}: {cantidad} paquetes/conexiones")
            
        print("\nDIRECCIONES IP MÁS CONTACTADAS:")
        # Intentar resolver nombres de host
        ips_resueltas = self.resolver_ips_a_nombres()
        for ip, cantidad in self.ips_destino.most_common(10):
            nombre = ips_resueltas.get(ip, ip)
            if nombre != ip:
                print(f"- {ip} ({nombre}): {cantidad} paquetes/conexiones")
            else:
                print(f"- {ip}: {cantidad} paquetes/conexiones")
        
        print("\nPUERTOS DE DESTINO MÁS UTILIZADOS:")
        for puerto, cantidad in self.puertos_destino.most_common(10):
            servicio = self.identificar_servicio(puerto)
            print(f"- Puerto {puerto} ({servicio}): {cantidad} paquetes/conexiones")
            
        print("\nDOMINIOS DNS CONSULTADOS:")
        for dominio, cantidad in self.dominios_dns.most_common(10):
            print(f"- {dominio}: {cantidad} consultas")
            
        print("\nPOSIBLES ANOMALÍAS DETECTADAS:")
        anomalias = self.detectar_anomalias()
        if anomalias:
            for anomalia in anomalias:
                print(f"- {anomalia}")
        else:
            print("- No se detectaron anomalías evidentes.")
    
    def visualizar_datos(self, directorio_salida="."):
        """Genera gráficos para visualizar los datos capturados"""
        if not self.paquetes_capturados and not self.conexiones:
            print("No hay datos para visualizar. Capture o cargue paquetes primero, o use las opciones sin privilegios.")
            return
            
        if not os.path.exists(directorio_salida):
            os.makedirs(directorio_salida)
            
        # Gráfico de protocolos
        if self.protocolos:
            protocols_data = self.protocolos.most_common(5)
            if protocols_data:
                protocolos, valores = zip(*protocols_data)
                plt.figure(figsize=(10, 6))
                plt.bar(protocolos, valores)
                plt.title("Distribución de Protocolos")
                plt.xlabel("Protocolo")
                plt.ylabel("Cantidad")
                plt.tight_layout()
                ruta_archivo = os.path.join(directorio_salida, "protocolos.png")
                plt.savefig(ruta_archivo)
                plt.close()
                print(f"\nGráfico de protocolos guardado como '{ruta_archivo}'")
            
        # Gráfico de IPs más contactadas
        if self.ips_destino:
            ips_data = self.ips_destino.most_common(5)
            if ips_data:
                ips, valores = zip(*ips_data)
                plt.figure(figsize=(10, 6))
                plt.bar(ips, valores)
                plt.title("IPs Más Contactadas")
                plt.xlabel("Dirección IP")
                plt.ylabel("Cantidad")
                plt.xticks(rotation=45)
                plt.tight_layout()
                ruta_archivo = os.path.join(directorio_salida, "ips_destino.png")
                plt.savefig(ruta_archivo)
                plt.close()
                print(f"Gráfico de IPs guardado como '{ruta_archivo}'")
                
        # Gráfico de puertos más utilizados
        if self.puertos_destino:
            puertos_data = self.puertos_destino.most_common(5)
            if puertos_data:
                puertos, valores = zip(*puertos_data)
                # Convertir puertos a strings para el gráfico
                puertos_str = [f"{p} ({self.identificar_servicio(p)})" for p in puertos]
                
                plt.figure(figsize=(10, 6))
                plt.bar(puertos_str, valores)
                plt.title("Puertos Más Utilizados")
                plt.xlabel("Puerto")
                plt.ylabel("Cantidad")
                plt.xticks(rotation=45)
                plt.tight_layout()
                ruta_archivo = os.path.join(directorio_salida, "puertos.png")
                plt.savefig(ruta_archivo)
                plt.close()
                print(f"Gráfico de puertos guardado como '{ruta_archivo}'")
            
    def identificar_servicio(self, puerto):
        """Identifica el servicio asociado a un puerto común"""
        servicios_comunes = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Alt"
        }
        return servicios_comunes.get(puerto, "Desconocido")
    
    def exportar_a_json(self, nombre_archivo="analisis_red.json"):
        """Exporta los datos de análisis a un archivo JSON"""
        if not self.paquetes_capturados and not self.conexiones:
            print("No hay datos para exportar. Realice una captura primero.")
            return False
            
        try:
            # Preparar datos para exportación
            datos_json = {
                "fecha_analisis": datetime.datetime.now().isoformat(),
                "fecha_inicio": self.fecha_inicio.isoformat(),
                "protocolos": dict(self.protocolos),
                "ips_destino": dict(self.ips_destino),
                "puertos_destino": {str(k): v for k, v in self.puertos_destino.items()},
                "dominios_dns": dict(self.dominios_dns),
                "conexiones": [{"src": c[0], "dst": c[1], "puerto": c[2], "protocolo": c[3], "cantidad": v} 
                              for c, v in self.conexiones.items()]
            }
            
            # Guardar a archivo
            with open(nombre_archivo, 'w', encoding='utf-8') as f:
                json.dump(datos_json, f, indent=4)
                
            print(f"Datos exportados a: {nombre_archivo}")
            return True
        except Exception as e:
            print(f"Error al exportar datos: {e}")
            return False

def mostrar_menu():
    """Muestra el menú principal del programa"""
    print("\nANALIZADOR DE TRÁFICO DE RED (SIN PRIVILEGIOS)")
    print("-" * 70)
    print("OPCIONES DE CAPTURA:")
    print("1. Cargar archivo PCAP")
    print("2. Analizar conexiones activas (no requiere privilegios)")
    print("3. Realizar escaneo básico de puertos (no requiere privilegios)")
    print("4. Obtener información DNS (no requiere privilegios)")
    print("5. Generar datos simulados para demostración")
    
    print("\nANÁLISIS Y SALIDA:")
    print("6. Generar informe")
    print("7. Visualizar datos")
    print("8. Exportar a JSON")
    print("9. Limpiar datos")
    print("0. Salir")
    
    try:
        opcion = int(input("\nSeleccione una opción: "))
        return opcion
    except ValueError:
        print("Por favor, ingrese un número válido.")
        return -1

def mostrar_info_sistema():
    """Muestra información básica del sistema"""
    print("\nINFORMACIÓN DEL SISTEMA:")
    print(f"Sistema Operativo: {platform.system()} {platform.release()}")
    print(f"Versión de Python: {platform.python_version()}")
    
    try:
        # Información de interfaces de red
        print("\nInterfaces de red disponibles:")
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"- {iface}: {addr.address}")
    except:
        print("No se pudo obtener información detallada de las interfaces de red.")

def ejecutar_analizador():
    """Función principal para ejecutar el analizador"""
    print("=" * 70)
    print("ANALIZADOR DE TRÁFICO DE RED (SIN PRIVILEGIOS)")
    print("=" * 70)
    print("Esta versión está optimizada para funcionar sin privilegios de administrador.")
    print("Utiliza métodos alternativos para obtener información de red.")
    
    # Mostrar información del sistema
    mostrar_info_sistema()
    
    analizador = AnalizadorTrafico()
    
    while True:
        opcion = mostrar_menu()
        
        if opcion == 1:
            # Cargar archivo PCAP
            archivo = input("Ingrese la ruta al archivo PCAP: ")
            analizador.cargar_pcap(archivo)
            
        elif opcion == 2:
            # Analizar conexiones activas
            analizador.obtener_conexiones_sin_privilegios()
            
        elif opcion == 3:
            # Realizar escaneo básico de puertos
            host = input("Dirección IP a escanear (Enter para localhost): ") or "127.0.0.1"
            puertos_str = input("Puertos a escanear (separados por comas, Enter para puertos comunes): ")
            
            if puertos_str:
                try:
                    puertos = [int(p.strip()) for p in puertos_str.split(",")]
                except ValueError:
                    print("Formato de puertos inválido. Usando puertos predeterminados.")
                    puertos = [80, 443, 8080, 22, 21, 25, 53, 3306, 5432]
            else:
                puertos = [80, 443, 8080, 22, 21, 25, 53, 3306, 5432]
                
            analizador.realizar_escaneo_basico_puertos(host, puertos)
            
        elif opcion == 4:
            # Obtener información DNS
            dominios_str = input("Dominios a consultar (separados por comas, Enter para dominios comunes): ")
            
            if dominios_str:
                dominios = [d.strip() for d in dominios_str.split(",")]
            else:
                dominios = ['google.com', 'github.com', 'facebook.com', 'microsoft.com', 'amazon.com']
                
            analizador.obtener_informacion_dns(dominios)
            
        elif opcion == 5:
            # Generar datos simulados
            try:
                cantidad = int(input("Cantidad de conexiones a simular (por defecto 100): ") or "100")
                analizador.generar_datos_simulados(cantidad)
            except ValueError:
                print("Por favor, ingrese un número válido.")
                
        elif opcion == 6:
            # Generar informe
            analizador.generar_informe()
            
        elif opcion == 7:
            # Visualizar datos
            directorio = input("Directorio para guardar gráficos (Enter para directorio actual): ") or "."
            analizador.visualizar_datos(directorio)
            
        elif opcion == 8:
            # Exportar a JSON
            nombre = input("Nombre del archivo JSON de salida (por defecto 'analisis_red.json'): ") or "analisis_red.json"
            analizador.exportar_a_json(nombre)
            
        elif opcion == 9:
            # Limpiar datos
            analizador = AnalizadorTrafico()
            print("Datos limpiados correctamente.")
            
        elif opcion == 0:
            # Salir
            print("\n¡Gracias por usar el Analizador de Tráfico de Red!")
            break
            
        else:
            print("Opción no válida. Por favor, intente de nuevo.")

def main():
    """Punto de entrada principal con manejo de argumentos por línea de comandos"""
    parser = argparse.ArgumentParser(description='Analizador de Tráfico de Red (Sin Privilegios)')
    
    parser.add_argument('-f', '--file', help='Archivo PCAP a analizar')
    parser.add_argument('-s', '--scan', help='IP a escanear')
    parser.add_argument('-d', '--dns', help='Dominios a consultar (separados por comas)')
    parser.add_argument('-c', '--connections', action='store_true', help='Analizar conexiones activas')
    parser.add_argument('-o', '--output', default='.', help='Directorio de salida para gráficos')
    parser.add_argument('--simulate', type=int, default=0, help='Generar datos simulados (cantidad)')
    
    args = parser.parse_args()
    
    analizador = AnalizadorTrafico()
    
    # Modo no interactivo
    if args.file or args.scan or args.dns or args.connections or args.simulate > 0:
        if args.file:
            analizador.cargar_pcap(args.file)
            
        if args.scan:
            analizador.realizar_escaneo_basico_puertos(args.scan)
            
        if args.dns:
            dominios = [d.strip() for d in args.dns.split(",")]
            analizador.obtener_informacion_dns(dominios)
            
        if args.connections:
            analizador.obtener_conexiones_sin_privilegios()
            
        if args.simulate > 0:
            analizador.generar_datos_simulados(args.simulate)
            
        analizador.generar_informe()
        analizador.visualizar_datos(args.output)
    else:
        # Modo interactivo
        try:
            ejecutar_analizador()
        except KeyboardInterrupt:
            print("\nPrograma interrumpido por el usuario.")
        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    main()