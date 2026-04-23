variable "nodes" {
  type    = list(string)
  default = ["helper1", "master1", "master2", "master3","worker1", "worker2"]
}

resource "yandex_compute_disk" "add_disk" {
  name = "add_disk"
  size = 10
  type = "network-hdd"
  zone = "ru-central1-d"
}

resource "yandex_compute_disk" "boot_disk" {
  count    = length(var.nodes)
  name     = "boot_disk-${var.nodes[count.index]}"
  image_id = "fd84gg15m6kjdembasoq"
  zone     = "ru-central1-d"
  type     = "network-ssd"
  size     = 20
}

resource "yandex_vpc_network" "network" {
  name = "network"
}

resource "yandex_vpc_subnet" "subnet" {
  name           = "subnet"
  network_id     = yandex_vpc_network.network.id
  v4_cidr_blocks = ["192.168.100.0/24"]
  zone           = "ru-central1-d"
}

resource "yandex_compute_instance" "vm" {
  count       = length(var.nodes)
  name        = "vm-${var.nodes[count.index]}"
  zone        = "ru-central1-d"
  platform_id = "standard-v2"
  resources {
    cores  = count.index == 0 ? 2 : 4
    memory = count.index == 0 ? 2 : 4
  }

  boot_disk {
    disk_id = yandex_compute_disk.boot_disk[count.index].id
  }

  dynamic "secondary_disk" {
    for_each = count.index == 0 ? [1] : []
    content {
      disk_id = yandex_compute_disk.add_disk.id
    }
  }

  network_interface {
    nat       = true
    subnet_id = yandex_vpc_subnet.subnet.id
  }
  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.ssh_keys.public_key_openssh}"
  }
  depends_on = [tls_private_key.ssh_keys]

}

resource "tls_private_key" "ssh_keys" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "ssh_keys" {
  filename        = "../ssh_keys/private"
  content         = tls_private_key.ssh_keys.private_key_openssh
  file_permission = 600
}

resource "local_file" "ansible_inventory" {
  filename = "../ansible/inventory.ini"
  content  = <<EOT
[helpers]
helper1 ansible_host=${yandex_compute_instance.vm[0].network_interface.0.nat_ip_address}     ip=${yandex_compute_instance.vm[0].network_interface.0.ip_address}
[masters]
master1    ansible_host=${yandex_compute_instance.vm[1].network_interface.0.nat_ip_address}     ip=${yandex_compute_instance.vm[1].network_interface.0.ip_address} 
master2    ansible_host=${yandex_compute_instance.vm[2].network_interface.0.nat_ip_address}     ip=${yandex_compute_instance.vm[2].network_interface.0.ip_address} 
master3    ansible_host=${yandex_compute_instance.vm[3].network_interface.0.nat_ip_address}     ip=${yandex_compute_instance.vm[3].network_interface.0.ip_address} 

[workers]
worker1    ansible_host=${yandex_compute_instance.vm[4].network_interface.0.nat_ip_address}       ip=${yandex_compute_instance.vm[4].network_interface.0.ip_address} 
worker2    ansible_host=${yandex_compute_instance.vm[5].network_interface.0.nat_ip_address}       ip=${yandex_compute_instance.vm[5].network_interface.0.ip_address} 

[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/k8s_kubeadm/ssh_keys/private
helper_ip=${yandex_compute_instance.vm[0].network_interface.0.ip_address}
[helpers:vars]
subnet=${yandex_vpc_subnet.subnet.v4_cidr_blocks[0]}

    EOT


}
