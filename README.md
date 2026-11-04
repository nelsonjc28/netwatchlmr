# NetWatch LMR

Aplicación web para supervisar dispositivos y visualizar la topología de una red local. Incluye una API con FastAPI, una interfaz web y almacenamiento local SQLite.

## Requisitos

- Python 3.10 o superior, o Docker con Docker Compose.
- Acceso a la red que se desea supervisar para que el descubrimiento de dispositivos funcione correctamente.

## Instalación con Python

1. Clona el repositorio y entra en la carpeta:

   ```bash
   git clone https://github.com/nelsonjc28/netwatchlmr.git
   cd netwatchlmr
   ```

2. Crea y activa un entorno virtual:

   **macOS o Linux**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

   **Windows (PowerShell)**

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. Instala las dependencias:

   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

4. Define una clave secreta propia para firmar las sesiones:

   **macOS o Linux**

   ```bash
   export NETWATCH_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
   ```

   **Windows (PowerShell)**

   ```powershell
   $env:NETWATCH_SECRET_KEY = py -c "import secrets; print(secrets.token_hex(32))"
   ```

5. Inicia el servidor:

   ```bash
   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```

6. Abre [http://localhost:8000](http://localhost:8000) en el navegador. La ruta `/health` permite comprobar que el servicio está activo.

La primera ejecución crea automáticamente la base de datos `netwatch.db` y un usuario inicial. Inicia sesión con **admin** / **admin123** y cambia la contraseña antes de utilizar la aplicación en una red compartida o accesible desde Internet. No expongas el servidor públicamente con las credenciales iniciales.

## Instalación con Docker

Con Docker y el complemento Docker Compose instalados, desde la raíz del proyecto ejecuta:

```bash
NETWATCH_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" docker compose up --build -d
```

En Windows PowerShell, define la clave antes de iniciar Compose:

```powershell
$env:NETWATCH_SECRET_KEY = py -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build -d
```

La aplicación estará disponible en [http://localhost:8000](http://localhost:8000). Para detenerla:

```bash
docker compose down
```

Compose publica el puerto `8000` y monta la carpeta del proyecto dentro del contenedor; la base de datos local se conserva en `netwatch.db`. Para descubrir dispositivos de la red local, ejecuta la aplicación en un equipo con acceso a esa red; el modo de red del contenedor puede requerir configuración adicional según el sistema operativo.

## Configuración

Edita `config.json` para ajustar el nombre del campus, las subredes a supervisar, el inventario de dispositivos, las alertas y las notificaciones de Telegram o webhook. El archivo incluido es una plantilla con la integración de Telegram desactivada. No guardes tokens, contraseñas ni datos privados en archivos que vayas a publicar.

La clave `NETWATCH_SECRET_KEY` debe ser privada, mantenerse estable entre reinicios y configurarse mediante una variable de entorno. No uses la clave de desarrollo predeterminada en un entorno compartido.

## Desarrollo y pruebas

Con el entorno virtual activado, ejecuta las pruebas desde la raíz:

```bash
python -m pytest -q
```
