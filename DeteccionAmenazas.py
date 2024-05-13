import pandas as pd
import numpy as np
import tensorflow as tf
from scapy.all import *
import requests

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
        # Analizar el paquete y realizar predicción de amenaza
        datos_ml = self.extraer_caracteristicas(paquete)
        if datos_ml:
            prediccion = self.modelo.predict(np.array([datos_ml]))
            if prediccion > 0.5:  # Umbral de predicción (ejemplo)
                self.tomar_accion(paquete, 'malicioso')

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

        # Normalizar características (opcional, dependiendo del tipo de datos)
        X_normalized = (X - X.min()) / (X.max() - X.min())

        return X_normalized, y

    def obtener_informacion_amenazas(self, ip):
        # Consultar servicios de reputación de IP
        url = f'https://api.example.com/reputacion?ip={ip}'
        respuesta = requests.get(url)
        datos_amenaza = respuesta.json()

        # Analizar los datos de amenaza
        es_riesgosa = datos_amenaza.get('es_riesgosa', False)

        return es_riesgosa

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
    ip_riesgosa = '123.456.789.0'
    es_riesgosa = detector.obtener_informacion_amenazas(ip_riesgosa)

    if es_riesgosa:
        print(f"La IP {ip_riesgosa} está en la lista negra. ¡Peligro!")
    else:
        print(f"La IP {ip_riesgosa} no representa una amenaza conocida.")
