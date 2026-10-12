# Лабораторна №4 — SSH тунелі між VM1 і VM2

Використовувати тільки власні VM або мережу з дозволом. Приклади нижче для Ubuntu/Debian з OpenSSH. Замініть `192.168.56.10` на реальну IP VM1; обидві VM повинні мати мережеву доступність. VM1 — SSH-сервер, VM2 — клієнт.

## 1. Підготовка
**На VM1:**
```bash
sudo apt update && sudo apt install -y openssh-server python3
sudo systemctl enable --now ssh
ip -4 addr
```
**На VM2:**
```bash
sudo apt update && sudo apt install -y openssh-client python3 curl
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C lab4
ssh-copy-id student@192.168.56.10
ssh student@192.168.56.10
```
Замість `student` вкажіть реальний обліковий запис VM1. Для безпечного доступу використовуйте ключі, окремі облікові записи, перевіряйте fingerprint SSH сервера. `PasswordAuthentication no` у `sshd_config` задавайте лише після перевірки ключового входу.

## 2. Тестові служби
На VM1 в окремому терміналі:
```bash
python3 -m http.server 8000 --bind 127.0.0.1
```
На VM2 в окремому терміналі (для перевірки remote forwarding):
```bash
python3 -m http.server 8001 --bind 127.0.0.1
```

## 3. Local forwarding (-L)
**На VM2:**
```bash
ssh -N -L 127.0.0.1:9000:127.0.0.1:8000 student@192.168.56.10
```
В іншому терміналі VM2: `curl http://127.0.0.1:9000` — результат вебслужби VM1.

## 4. Remote / reverse forwarding (-R)
**На VM2:**
```bash
ssh -N -R 127.0.0.1:9001:127.0.0.1:8001 student@192.168.56.10
```
В іншому терміналі VM1: `curl http://127.0.0.1:9001` — результат вебслужби VM2.

## 5. Dynamic forwarding (-D)
**На VM2:**
```bash
ssh -N -D 127.0.0.1:1080 student@192.168.56.10
```
В іншому терміналі VM2:
```bash
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8000
```
SOCKS5 запит іде через VM1; зазначена адреса 127.0.0.1:8000 в такій команді — на VM1.

**Увага:** кожну SSH команду з `-N` запускати в окремому терміналі та зупиняти Ctrl+C. Якщо порти зайняті, обирайте інші. SSH-сервер може забороняти forwarding через налаштування `AllowTcpForwarding`, `PermitOpen` або `PermitListen`. Прив'язка до `127.0.0.1` не робить порти доступними для інших комп'ютерів.
