import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler
from scapy.all import *
import requests
import socket
import struct

class DetectorAmenazas:
    def __init__(self, modelo_archivo):
        self.modelo = self.cargar_modelo(modelo_archivo)

    def cargar_modelo(self, archivo):
        # Cargar modelo de machine learning desde archivo
        modelo = tf.keras.models.load_model(archivo)
        return modelo

    def extraer_caracteristicas(self, paquete):
        # Inicializar un diccionario para almacenar características
        caracteristicas = {}

        # Verificar el tipo de protocolo del paquete
        if IP in paquete:
            ip_src = paquete[IP].src
            ip_dst = paquete[IP].dst
            caracteristicas['src_ip'] = ip_src
            caracteristicas['dst_ip'] = ip_dst

        # Extraer características de la capa de transporte (TCP o UDP)
        if TCP in paquete:
            tcp_sport = paquete[TCP].sport
            tcp_dport = paquete[TCP].dport
            caracteristicas['tcp_sport'] = tcp_sport
            caracteristicas['tcp_dport'] = tcp_dport
            caracteristicas['protocolo'] = 'TCP'
        elif UDP in paquete:
            udp_sport = paquete[UDP].sport
            udp_dport = paquete[UDP].dport
            caracteristicas['udp_sport'] = udp_sport
            caracteristicas['udp_dport'] = udp_dport
            caracteristicas['protocolo'] = 'UDP'

        return caracteristicas

    def analizar_trafico(self, paquete):
        # Extraer características del paquete
        datos_ml = self.extraer_caracteristicas(paquete)

        if datos_ml:
            # Convertir el diccionario de características en un vector numérico
            caracteristicas_vector = self.convertir_a_vector(datos_ml)

            # Realizar la predicción de amenaza
            prediccion = self.modelo.predict(np.array([caracteristicas_vector]))
            if np.max(prediccion) > 0.5:  # Umbral de predicción (ejemplo)
                self.tomar_accion(paquete, 'malicioso')
                

    def convertir_a_vector(self, datos_ml):
        # Definir el orden de las características para garantizar consistencia
        orden_caracteristicas = ['src_ip', 'dst_ip', 'tcp_sport', 'tcp_dport', 'udp_sport', 'udp_dport', 'protocolo']

        # Crear un vector numérico con características ordenadas
        caracteristicas_vector = []
        for caracteristica in orden_caracteristicas:
            if caracteristica in datos_ml:
                valor = datos_ml[caracteristica]
                if caracteristica == 'protocolo':
                    valor = 1 if valor == 'TCP' else 0  # Codificar 'TCP' como 1 y 'UDP' como 0
                elif caracteristica in ['src_ip', 'dst_ip']:
                    valor = struct.unpack("!I", socket.inet_aton(valor))[0]  # Convertir dirección IP a entero de 32 bits
                else:
                    valor = int(valor)  # Convertir a int
            else:
                valor = 0  # Valor por defecto para características faltantes

            caracteristicas_vector.append(valor)

        return caracteristicas_vector

    def tomar_accion(self, paquete, tipo):
        # Tomar acción apropiada según el tipo de amenaza detectada
        if tipo == 'malicioso':
            print(f"Alerta: Tráfico malicioso detectado en {paquete.summary()}")

    def iniciar_captura(self, filtro=None):
        # Iniciar la captura de paquetes
        sniff(prn=self.analizar_trafico, filter=filtro, store=0)

    def cargar_datos_entrenamiento(self, ruta_datos):
        # Cargar datos de entrenamiento desde un archivo CSV
        data = pd.read_csv(ruta_datos)

        # Separar características (X) y etiquetas (y)
        X = data.drop('etiqueta', axis=1)  # Asume que 'etiqueta' es la columna de etiquetas
        y = data['etiqueta']

        return X, y

    def preprocesar_datos(self, X, y):
        # Convertir etiquetas a valores numéricos
        y = np.where(y == 'malicioso', 1, 0)

        # Convertir X a una matriz de numpy y manejar valores faltantes
        X_numeric = X.select_dtypes(include=[np.number])
        if not X_numeric.empty:
            scaler = MinMaxScaler()
            X_normalized = pd.DataFrame(scaler.fit_transform(X_numeric.fillna(0)), columns=X_numeric.columns)
        else:
            X_normalized = pd.DataFrame()

        # Manejar características no numéricas
        X_non_numeric = X.select_dtypes(exclude=[np.number])
        X_preprocessed = pd.concat([X_normalized, X_non_numeric], axis=1)

        return X_preprocessed, y

    def obtener_informacion_amenazas(self, ip):
      url = f'https://93.184.216.34/reputacion?ip=93.184.216.34'  # Reemplaza con la URL real de la API
      try:
          respuesta = requests.get(url, verify=True)
          respuesta.raise_for_status()  # Genera una excepción para códigos de estado distintos a 200
          datos_amenaza = respuesta.json()
          return datos_amenaza.get('es_riesgosa', False)  # Maneja la posible falta de la clave
      except requests.exceptions.RequestException as e:
          print(f"Error al consultar información de amenazas para {ip}: {e}")
          return False  # O cualquier valor predeterminado para "no encontrado"


# Ejemplo de uso:
if __name__ == "__main__":
    # Crear instancia del detector de amenazas
    detector = DetectorAmenazas('modelo_ml.h5')  # Reemplaza 'modelo_ml.h5' con tu archivo de modelo

    # Cargar y preprocesar datos de entrenamiento
    X_train, y_train = detector.cargar_datos_entrenamiento('datos_malware.csv')
    X_train_processed, y_train_processed = detector.preprocesar_datos(X_train, y_train)

    # Iniciar la captura de paquetes en una subred específica
    detector.iniciar_captura(filtro="net 192.168.1.0/24")

    # Ejemplo de consulta de información de amenazas para una IP específica
    ip_riesgosa = '93.184.216.34'
    es_riesgosa = detector.obtener_informacion_amenazas(ip_riesgosa)

    if es_riesgosa:
        print(f"La IP {ip_riesgosa} está en la lista negra. ¡Peligro!")
    else:
        print(f"La IP {ip_riesgosa} no representa una amenaza conocida.")
