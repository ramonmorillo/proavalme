# PROA Valme

La aplicación web está en [docs/index.html](docs/index.html). Funciona en el navegador y procesa los ficheros localmente. No necesita instalación ni servidor de aplicación.

## Publicación

En GitHub Pages, seleccionar **Deploy from a branch**, rama **main**, carpeta **/docs**. En cuentas gratuitas GitHub exige que el repositorio sea público para esta opción. Solo se sirve el contenido de `docs/` en la web, aunque cambiar la visibilidad también permite consultar el resto del repositorio y su historial. La versión anterior con servidor queda conservada como referencia.

## Primer uso

1. Abrir la aplicación y pulsar **Cargar datos ficticios**.
2. Filtrar por indicador, ámbito, grupo, elemento o periodo. Usar **Imprimir / guardar PDF filtrado** o **Exportar CSV filtrado** para generar el informe.
3. Elegir un código de al menos 14 caracteres y guardar el histórico cifrado. Cerrar el archivo de trabajo y volver a abrirlo con el mismo código.
4. Para trabajar con datos propios, cerrar el ejemplo ficticio y descargar la plantilla. Incorporar el CSV UTF-8 o el XLSX con la cabecera de la plantilla. Un fichero corregido sustituye los bloques de periodo, indicador y ámbito que se confirmen. Conservar el archivo cifrado previo para poder recuperar la versión anterior.

El histórico se comparte como archivo cifrado por el canal autorizado. El código protege ese archivo y no hay cuentas de usuario ni sincronización automática. Los archivos fuente, los históricos y los informes se guardan fuera de GitHub. La plantilla admite valores ya validados, incluidas las tasas anuales cuando estén disponibles. El XLS histórico y el PDF PIRASOA requieren adaptación previa.
