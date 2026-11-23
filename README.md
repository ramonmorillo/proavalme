# PROA Valme

Panel privado de seguimiento de antimicrobianos. Incluye cuentas individuales, carga validada, histórico de versiones, informes y exportación. La demostración anterior sigue en `index.html` y la aplicación con servidor arranca desde `app.py`.

## Prueba local

1. Con Python 3.10 o posterior, instalar `python -m pip install -r requirements.txt`. CSV funciona también con la biblioteca estándar.
2. Ejecutar `python app.py add-user CORREO editor` para cada persona que vaya a cargar datos. Usar `reader` para consulta e informes. La contraseña temporal se introduce en el aviso interactivo.
3. Ejecutar `python app.py serve` y abrir http://127.0.0.1:8080.
4. En el primer acceso, cambiar la contraseña temporal. En Cargar datos, descargar la plantilla ficticia y recorrer la vista previa, confirmación, panel e informe. Para generar un PDF, abrir el informe y seleccionar Guardar como PDF en el diálogo de impresión del navegador.

## Formato y criterios

CSV UTF-8 o XLSX con una hoja Datos y cabecera `periodo;indicador;ambito;grupo;elemento;unidad;valor`. Usar periodos como 2025-T1 o 2025. Indicadores admitidos: consumo, gasto y microbiologia. Unidades de consumo y gasto: DDD/1.000 estancias y EUR, respectivamente. Cargar microbiología con la unidad que documente su fuente. Usar Hospital o el nombre del GFH para consumo y el ámbito de origen para gasto. La importación conserva ceros y exige valores explícitos. Los totales y tasas anuales deben venir previamente validados. Los ficheros históricos XLS, los PDF PIRASOA y las plantillas originales por GFH requieren un adaptador o una normalización previa.

Una sustitución abarca todas las filas de cada combinación periodo, indicador y ámbito del fichero. Revisar que el lote corregido esté completo antes de confirmar. Las cargas antiguas quedan disponibles para exportación desde Histórico.

## Instalación compartida

Usar un servidor autorizado con HTTPS, almacenamiento persistente protegido y copias de seguridad de SQLite mediante su mecanismo de backup. Establecer `PROAVALME_DB` con la ruta del fichero persistente y `PROAVALME_HTTPS=1` para cookies seguras. Inicializar con `python app.py init` y ejecutar, detrás del proxy HTTPS, `gunicorn --bind 127.0.0.1:8080 app:application`. El comando serve es para pruebas locales. Restringir el acceso al servidor por red según el entorno. Provisionar las cuentas en ese mismo almacenamiento y entregar las credenciales temporales por un canal autorizado. Los ficheros clínicos y la base de datos permanecen fuera del repositorio.
