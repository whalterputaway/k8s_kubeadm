# Тестовый стенд
- helper1 - вспомогательная машина (vCPU=1, RAM=1, SSD=20, HDD=10)
  - NFS-сервер
- master1 (vCPU 2, RAM 4, SSD=15)
- master2 (vCPU 2, RAM 4, SSD=15)
- master3 (vCPU 2, RAM 4, SSD=15)
- worker1 (vCPU 2, RAM 4, SSD=15)
- worker2 (vCPU 2, RAM 4, SSD=15)

OC: Ubuntu 24.04 LTS

# Подготовительные действия
Установка NFS-сервер на helper1 и NFS-клиентов на остальные узлы (master1, worker1, worker2) воспроизводится ansible-плейбуком nfs.yml.

***По умолчанию у меня монтируется /dev/vdb. Если у вас другое устройство, потребуется поменять в плейбуке переменную device!***

Проиграть - `prepare.yml`

# HA Kubernetes
- haproxy
- keepalived