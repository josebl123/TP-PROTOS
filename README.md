
# 🧩 MAEP-S5 Protocol & Usage

## Introducción
Este documento describe el protocolo administrativo del servidor SOCKS5 MAEP-S5, incluyendo la autenticación, flujos de usuario y administrador, comandos de configuración, y cómo usar tanto el servidor como el cliente.

### Protocolos de Comunicación - Grupo 16 - Primer Cuatrimestre 2025

## Índice

- [Protocolo Administrativo](#protocolo-administrativo)
- [Autenticación](#autenticación)
- [Flujos de Usuario y Administrador](#flujos-de-usuario-y-administrador)
- [Comandos Config de Admin](#comandos-config-de-admin)
- [Uso del Servidor](#uso-del-servidor)
- [Uso del Cliente](#uso-del-cliente)
- [Compilación y Ejecución](#compilación-y-ejecución)

---

## 🧪 Protocolo Administrativo

### Autenticación

**Cliente → Servidor:**

```
VERSION RSV ULEN USERNAME PLEN PASSWORD
```

**Servidor → Cliente:**

```
VERSION RSV STATUS ROLE
```

- `STATUS`: `0x00 = Success`, `0x01 = Failure`
- `ROLE`: `0x00 = USER`, `0x01 = ADMIN`

---

## 👤 Flujos de Usuario y Administrador

### 🧍 USER FLOW

1. Tras autenticarse exitosamente como `USER`, el servidor responde:

```
VERSION RSV STATUS
```

- `STATUS`: `0x00 = OK`, `0x01 = Error`
- Luego se envían métricas en **texto plano**.

---

### 👑 ADMIN FLOW

1. Tras autenticarse exitosamente como `ADMIN`, el cliente envía:

```
VERSION RSV CMD ULEN USERNAME
```

- `CMD`:
    - `0x00 = STATS`
    - `0x01 = CONFIG`
- `USERNAME`: objetivo de la consulta/configuración (puede ser vacío para métricas globales)

**Servidor → Cliente:**

```
VERSION RSV STATUS
```

- `STATUS`:
    - `0x00 = Stats Success` → métricas en texto
    - `0x01 = Config Success` → espera comandos binarios

---

## 🛠️ Comandos CONFIG de Admin

Formato general:

```
VERSION RSV CODE ULEN USERNAME PLEN PASSWORD BUFFERSIZE
```

| CODE | Acción                   | Descripción                                                     |
|------|--------------------------|-----------------------------------------------------------------|
| 0x00 | Cambiar buffer           | Solo se rellena `BUFFERSIZE` (`uint32_t` en network byte order) |
| 0x01 | Accepts no-auth          | Ignora username/password                                        |
| 0x02 | Not accepts no-auth      | Ignora username/password                                        |
| 0x03 | Agregar usuario          | Requiere `USERNAME_LEN` `USERNAME`  `PASSWORD_LEN` `PASSWORD`    |
| 0x04 | Eliminar usuario         | Solo `USERNAME`                                                 |
| 0x05 | Hacer admin              | Solo `USERNAME`                                                 |

**Respuesta de servidor:**

```
VERSION RSV CODE STATUS
```

- `STATUS`: `0x00 = Success`, `0x01 = Failure`

---

## 🖥️ Uso del Servidor SOCKS5

```bash
./bin/server [opciones]
```

### Opciones

| Flag      | Descripción                                           |
|-----------|-------------------------------------------------------|
| `-h`      | Ayuda                                                 |
| `-l`      | Dirección del proxy SOCKS (default: `127.0.0.1`)      |
| `-L`      | Dirección del puerto de configuración (default igual) |
| `-p`      | Puerto SOCKS (default: 1080)                          |
| `-P`      | Puerto configuración (default: 8080)                  |
| `-u u:p`  | Agrega usuario común                                  |
| `-a u:p`  | Agrega usuario admin                                  |
| `-v`      | Muestra versión y termina                             |

> Ejemplo:
```bash
./bin/server -u pepe:1234 -a admin:adminpass -p 1080 -P 9090
```

---

## 👨‍💻 Uso del Cliente Administrativo

```bash
./bin/client --login user:pass [opciones]
```

### Autenticación (obligatorio)

- `--login user:pass` → login como USER o ADMIN

### Flags de métrica (requiere ser ADMIN)

- Si no se especifican flags, se obtienen métricas de usuario propias.


| Flag        | Descripción                               |
|-------------|-------------------------------------------|
| `-G`        | Métricas globales                         |
| `-s <user>` | Métricas específicas de usuario           |

### Flags de configuración (requiere ser ADMIN)

| Flag       | Descripción                                  |
|------------|----------------------------------------------|
| `-b <n>`   | Cambiar tamaño de buffer                     |
| `-n`       | Habilitar `no-auth`                          |
| `-N`       | Deshabilitar `no-auth`                       |
| `-u u:p`   | Agregar usuario                              |
| `-r <u>`   | Eliminar usuario                             |
| `-m <u>`   | Convertir usuario en admin                   |

### Conexión

| Flag       | Descripción                                 |
|------------|---------------------------------------------|
| `-a <ip>`  | Dirección del servidor (default: `127.0.0.1`)|
| `-p <port>`| Puerto del protocolo admin (default: 8080)   |

> Ejemplos:

- Obtener métricas globales:
```bash
./bin/client --login admin:adminpass -g
```

- Cambiar tamaño de buffer:
```bash
./bin/client --login admin:adminpass -b 2048
```

- Agregar un usuario:
```bash
./bin/client --login admin:adminpass -u nuevo:clave
```

---

## 🔧 Compilación y Ejecución

```bash
make clean all

./bin/server -a admin:pass
./bin/client --login admin:pass -g
```
