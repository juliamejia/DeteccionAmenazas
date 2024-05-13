import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# Definir la arquitectura del modelo
modelo = Sequential([
    Dense(64, activation='relu', input_shape=(7,)),  # 7 es el número de características
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')  # Salida binaria (0 o 1)
])

# Compilar el modelo
modelo.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Guardar el modelo aleatorio en un archivo
modelo.save('modelo_ml.h5')
