Panel de Control de Seguridad Avanzado - LHPSecure

Una plataforma web profesional para la orquestación de herramientas de ciberseguridad, construida con una arquitectura robusta y comunicación en tiempo real.
Dependencias

Para el correcto funcionamiento del panel, es necesario contar con una serie de dependencias tanto a nivel de sistema operativo como de librerías de Python. El script install_advanced.sh se encarga de instalar la mayoría de ellas.
Dependencias del Sistema (Herramientas)

Estas herramientas son la base del panel y deben estar instaladas en un sistema operativo basado en Debian/Ubuntu.

    Gestores de Paquetes y Utilidades Base:

        apt-get

        git

        curl y wget

        python3, python3-pip, python3-venv

        ruby-full, build-essential (para dependencias de Ruby)

        snapd (para instalar Amass)

    Herramientas de Seguridad Principales:

        Nmap: Escáner de redes y puertos.

        Nikto: Escáner de vulnerabilidades web.

        SQLMap: Herramienta de inyección SQL.

        Wfuzz: Fuzzer para aplicaciones web.

        Gobuster: Herramienta para descubrir directorios y archivos.

        Masscan: Escáner de puertos masivo y rápido.

        WhatWeb: Identificador de tecnologías web.

        Sublist3r: Enumerador de subdominios.

        WPScan: Escáner de vulnerabilidades para WordPress.

        Amass: Herramienta de descubrimiento de activos de red.

        Metasploit Framework: Plataforma para el desarrollo y ejecución de exploits.

Dependencias de Python

Estas librerías son necesarias para el backend y se instalan dentro de un entorno virtual para no afectar el sistema global.

    Flask: Micro-framework para crear la aplicación web y la API.

    Flask-SocketIO: Extensión para Flask que permite la comunicación en tiempo real mediante WebSockets.

    eventlet: Servidor WSGI de alto rendimiento, recomendado para producción con Flask-SocketIO.

Guía de Despliegue
Paso 1: Preparar el Servidor

    Requisito: Un servidor con Ubuntu 20.04/22.04 o Debian.

    Asegúrate de que todos los archivos (install_advanced.sh, app.py, index.html) estén en el mismo directorio.

    El script app.py ejecutará automáticamente el instalador install_advanced.sh la primera vez.

Paso 2: Configurar el Entorno de Python

El backend requiere librerías específicas que deben instalarse en un entorno virtual. Elige una de las dos opciones siguientes.

Opción A: Usando venv (Estándar de Python)

    Crea y activa un entorno virtual:

    python3 -m venv venv
    source venv/bin/activate

    Instala las dependencias de Python con pip:

    pip install Flask Flask-SocketIO eventlet

Opción B: Usando pipenv

Si prefieres usar pipenv, el proceso es más directo.

    Instala las dependencias. pipenv gestionará el entorno automáticamente:

    pipenv install Flask Flask-SocketIO eventlet

    Para ejecutar la aplicación, primero activa el shell del entorno:

    pipenv shell

Paso 3: Iniciar el Panel

Con el entorno virtual activado (ya sea con source venv/bin/activate o pipenv shell), simplemente ejecuta el script principal de Python:

python3 app.py

El panel estará disponible en http://<IP_DE_TU_SERVIDOR>:5000.
Cómo Extender el Panel

Añadir nuevas herramientas es muy sencillo:

    Abre app.py.

    Localiza el diccionario ALLOWED_TOOLS.

    Añade una nueva entrada siguiendo la estructura existente. El frontend se adaptará automáticamente.
