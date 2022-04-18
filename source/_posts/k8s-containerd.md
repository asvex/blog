---
title: 二进制高可用安装
cover: https://acg.toubiec.cn/random.php
tags: kubernetes
---

ubuntu install kubernetes(containerd)

<!-- more -->

## 一、Prepare

### 1、system

```sh
# 1、sources.list
mv /etc/apt/sources.list /etc/apt/sources.list.bak
cat  /etc/apt/sources.list.bak |grep -v "#" |grep -v "^$" > sources.list
sed -i s/archive.ubuntu.com/mirrors.ustc.edu.cn/g /etc/apt/sources.list
sed -i s/security.ubuntu.com/mirrors.ustc.edu.cn/g /etc/apt/sources.list
apt -y update && apt -y upgrade

# 2、timedatectl
sed -i s/en_US/C/g /etc/default/locale
timedatectl set-timezone Asia/Shanghai

# 3、bash-completion
sed -i 97,99s/#//g /root/.bashrc

# 4、ssh
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
passwd root << "EOF"
password
password
EOF
systemctl reload ssh

# 5、hosts
vim /etc/hosts
10.0.0.20 k8s-master00
10.0.0.21 k8s-master01
10.0.0.22 k8s-master02
10.0.0.23 k8s-node01
10.0.0.24 k8s-node02
10.0.0.25 k8s-bl-master

# 6、ssh-keygen
ssh-keygen -t rsa
for i in `cat /root/*.txt`;do echo $i;ssh-copy-id -i .ssh/id_rsa.pub $i;done

# 7、swap
swapoff -a
sed -i '/swap/s/^\(.*\)$/#\1/g' /etc/fstab

# 8、network
net=`cat /etc/netplan/00-installer-config.yaml |awk 'NR==4{print $1}'`
sed -i "s/${net}/eth0:/g" /etc/netplan/00-installer-config.yaml
sed -i '11s/""/"net.ifnames=0 biosdevname=0"/g' /etc/default/grub
update-grub
reboot
```
### 2、ipvs

```sh
apt -y install ipvsadm ipset sysstat conntrack libseccomp2 libseccomp-dev
cat > /etc/modules-load.d/ipvs.conf << EOF
ip_vs
ip_vs_lc
ip_vs_wlc
ip_vs_rr
ip_vs_wrr
ip_vs_lblc
ip_vs_lblcr
ip_vs_dh
ip_vs_sh
ip_vs_fo
ip_vs_nq
ip_vs_sed
ip_vs_ftp
nf_conntrack
ip_tables
ip_set
xt_set
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
EOF
systemctl restart systemd-modules-load.service
lsmod |grep -e ip_vs -e nf_conntrack_ipv4
```

### 3、containerd

#### 3.1、download containerd

```sh
wget https://github.com/containerd/containerd/releases/download/v1.6.1/cri-containerd-cni-1.6.1-linux-amd64.tar.gz
tar --no-overwrite-dir -C / -xzf cri-containerd-cni-1.6.1-linux-amd64.tar.gz
systemctl daemon-reload
systemctl enable --now containerd
```

#### 3.2、config.toml

```sh
containerd config default > /etc/containerd/config.toml
---
sed -i "s#k8s.gcr.io#registry.aliyuncs.com/google_containers#g" /etc/containerd/config.toml
sed -i "s#SystemdCgroup = false#SystemdCgroup = true#g" /etc/containerd/config.toml
sed -i '153a\        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]' /etc/containerd/config.toml  # 8个空格 # endpoint 10个空格
sed -i '154a\          endpoint = ["https://registry.aliyuncs.com"]' /etc/containerd/config.toml
```

#### 3.3、crictl.yaml

```sh
mv /etc/crictl.yaml /etc/crictl.yaml.bak
cat > /etc/crictl.yaml << "EOF"
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 0
debug: false
pull-image-on-create: false
disable-pull-on-run: false
EOF
```

## 二、High availability

### 1、nginx.conf

```sh
apt -y install nginx
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
vim /etc/nginx/nginx.conf
---
...
...
stream {
          
        log_format main '$remote_addr $upstream_addr - [$time_local] $status $upstream_bytes_sent';
          
        access_log /var/log/nginx/k8s-access.log main;
        
        upstream k8s-apiserver {
                server 10.0.0.20:6443;
                server 10.0.0.21:6443;
                server 10.0.0.22:6443;
        }
    
        server {
                listen 6444; 
                proxy_pass k8s-apiserver;
        }
}

http {
		log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';
        ...
        ...
}
---
systemctl enable --now nginx.service
systemctl status nginx.service
```

### 2、keepalived.conf

```sh
apt -y install keepalived
#keepalived config
cat > /etc/keepalived/keepalived.conf << "EOF"
global_defs {
    notification_email {
      acassen@firewall.loc
      failover@firewall.loc
      sysadmin@firewall.loc
    }
    notification_email_from Alexandre.Cassen@firewall.loc
    smtp_server 127.0.0.1
    smtp_connect_timeout 30 
    router_id NGINX_MASTER
}

vrrp_script check_nginx {
  script "/etc/keepalived/check_nginx.sh"
  interval 5
  weight -1
  fall 2
  rise 1
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0 # 修改为实际网卡名
    virtual_router_id 51 # VRRP 路由 ID 实例，每个实例是唯一的
    priority 100 # 优先级，备服务器设置 90
    advert_int 1 # 指定 VRRP 心跳包通告间隔时间，默认 1 秒
    authentication {
        auth_type PASS
        auth_pass K8SHA_KA_AUTH
    }
    # 虚拟 IP
    virtual_ipaddress {
        10.0.0.25/24
    }
    track_script {
        check_nginx
    }
}
EOF
#health config
cat > /etc/keepalived/check_nginx.sh << "EOF"
#!/bin/bash 
count=$(ps -ef |grep nginx | grep sbin | egrep -cv "grep|$$") 
if [ "$count" -eq 0 ];then 
  systemctl stop keepalived 
fi
EOF
---
systemctl enable --now keepalived.service
systemctl status keepalived.service
```

## 三、Master

### 1、cfssl

```sh
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl_1.6.1_linux_amd64 -O /usr/local/bin/cfssl
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssljson_1.6.1_linux_amd64 -O /usr/local/bin/cfssljson
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.1/cfssl-certinfo_1.6.1_linux_amd64 -O /usr/local/bin/cfssl-certinfo
chmod +x /usr/local/bin/cfssl*
chown -Rf root:root /usr/local/bin/cfssl*
```

### 2、etcd

#### 2.1、mkdir directory

```sh
# all Master
# 1、etcd-ssl
mkdir -p /etc/etcd/ssl/
# 2、etcd-WorkingDirectory
mkdir -p /var/lib/etcd/default.etcd
# 3、kubernetes-ssl
mkdir -p /etc/kubernetes/ssl
# 4、kubernetes-log
mkdir -p /var/log/kubernetes
```

#### 2.2、ca certificate

```sh
# master00
mkdir -p ~/work
cd ~/work/
---
cat > ca-csr.json << "EOF"
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "k8s",
      "OU": "system"
    }
  ]
}
EOF
---
cat > ca-config.json << "EOF"
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
EOF
---
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
cp ca*.pem /etc/etcd/ssl/
---
# send to other master
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/etcd/ssl/ca*.pem $i:/etc/etcd/ssl;done
```

#### 2.3、etcd certificate

```sh
cat > etcd-csr.json << "EOF"
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.25"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "k8s",
      "OU": "system"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
cp etcd*.pem /etc/etcd/ssl/
---
# send to other
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/etcd/ssl/etcd*.pem $i:/etc/etcd/ssl;done
```

#### 2.4、install etcd{,ctl}

```sh
# download etcd
wget https://github.com/etcd-io/etcd/releases/download/v3.5.0/etcd-v3.5.0-linux-amd64.tar.gz
# tar etcd-*.tar.gz
tar -xf etcd-v3.5.0-linux-amd64.tar.gz --strip-components=1 -C ~/work/ etcd-v3.5.0-linux-amd64/etcd{,ctl}
chown -Rf root:root etcd*
cp -arp etcd* /usr/local/bin/
# send to other
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /usr/local/bin/etcd{,ctl} $i:/usr/local/bin/;done
```

#### 2.5、etcd.conf

```sh
cat > /etc/etcd/etcd.conf << "EOF"
ETCD_NAME='etcd1'
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://10.0.0.20:2380" # change ip
ETCD_LISTEN_CLIENT_URLS="https://10.0.0.20:2379,http://127.0.0.1:2379" # change ip
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://10.0.0.20:2380" # change ip
ETCD_ADVERTISE_CLIENT_URLS="https://10.0.0.20:2379" # change ip
ETCD_INITIAL_CLUSTER="etcd1=https://10.0.0.20:2380,etcd2=https://10.0.0.21:2380,etcd3=https://10.0.0.22:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
EOF
```

#### 2.6、etcd.service

```sh
cat > /usr/lib/systemd/system/etcd.service << "EOF"
[Unit]
Description=Etcd Service
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=-/etc/etcd/etcd.conf
WorkingDirectory=/var/lib/etcd/
ExecStart=/usr/local/bin/etcd \
 --cert-file=/etc/etcd/ssl/etcd.pem \
 --key-file=/etc/etcd/ssl/etcd-key.pem \
 --trusted-ca-file=/etc/etcd/ssl/ca.pem \
 --peer-cert-file=/etc/etcd/ssl/etcd.pem \
 --peer-key-file=/etc/etcd/ssl/etcd-key.pem \
 --peer-trusted-ca-file=/etc/etcd/ssl/ca.pem \
 --peer-client-cert-auth \
 --client-cert-auth
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
---
# send to other
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /usr/lib/systemd/system/etcd.service $i:/usr/lib/systemd/system/;done
```

#### 2.7、start etcd.service

```sh
# 1、start etcd
systemctl daemon-reload
systemctl enable --now etcd.service
systemctl status etcd.service
# 2、check etcd
ETCDCTL_API=3
etcdctl --endpoints=https://10.0.0.20:2379,https://10.0.0.21:2379,https://10.0.0.22:2379 --write-out=table --cacert=/etc/etcd/ssl/ca.pem --cert=/etc/etcd/ssl/etcd.pem --key=/etc/etcd/ssl/etcd-key.pem endpoint health
+----------------------------+--------+-------------+-------+
|          ENDPOINT          | HEALTH |    TOOK     | ERROR |
+----------------------------+--------+-------------+-------+
| https://10.0.0.20:2379     |   true | 16.188005ms |       |
| https://10.0.0.21:2379     |   true | 16.693314ms |       |
| https://10.0.0.22:2379     |   true | 16.089367ms |       |
+----------------------------+--------+-------------+-------+
```

#### 2.8、kube{...}

```sh
# 1、download
wget https://dl.k8s.io/v1.23.5/kubernetes-server-linux-amd64.tar.gz
# 2、tar
tar -xf kubernetes-server-linux-amd64.tar.gz --strip-components=3 -C ~/work kubernetes/server/bin/kube{let,ctl,-apiserver,-controller-manager,-scheduler,-proxy}

scp kube{ctl,-apiserver,-controller-manager,-scheduler} /usr/local/bin/
# 3、kube{let,ctl,-apiserver,-controller-manager,-scheduler,-proxy}
for i in `cat ~/MasterNodes.txt`;do echo $i;scp ~/work/kube{ctl,-apiserver,-controller-manager,-scheduler} $i:/usr/local/bin/;done
# 4、kube{let,-proxy}
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kube{let,-proxy} $i:/usr/local/bin/;done
# 5、send pem
cp /etc/etcd/ssl/ca*.pem /etc/kubernetes/ssl/
for i in `cat ~/WorkNodes.txt`;do echo $i;scp /etc/etcd/ssl/ca*.pem $i:/etc/kubernetes/ssl/;done
```

### 3、kube-apiserver

#### 3.1、token.csv

```sh
cat  > /etc/kubernetes/token.csv <<EOF
$(head -c 16 /dev/urandom | od -An -t x | tr -d ' '),kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/token.csv $i:/etc/kubernetes/;done
```

#### 3.2、kube-apiserver certificate

```sh
cat > kube-apiserver-csr.json << "EOF"
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.23",
    "10.0.0.24",
    "10.0.0.25",
    "10.96.0.1",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "k8s",
      "OU": "system"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-apiserver-csr.json | cfssljson -bare kube-apiserver
cp kube-apiserver*.pem /etc/kubernetes/ssl/
for i in `cat ~/MasterNodes.txt`;do echo $i;scp ~/work/kube-apiserver*.pem $i:/etc/kubernetes/ssl/;done
```

#### 3.3、kube-apiserver.conf

```sh
# change --bind-address= and --advertise-address=
---
cat > /etc/kubernetes/kube-apiserver.conf << "EOF"
KUBE_APISERVER_OPTS="--enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \
 --anonymous-auth=false \
 --bind-address=10.0.0.20 \
 --secure-port=6443 \
 --advertise-address=10.0.0.20 \
 --insecure-port=0 \
 --authorization-mode=Node,RBAC \
 --runtime-config=api/all=true \
 --enable-bootstrap-token-auth \
 --service-cluster-ip-range=10.96.0.0/16 \
 --token-auth-file=/etc/kubernetes/token.csv \
 --service-node-port-range=30000-50000 \
 --tls-cert-file=/etc/kubernetes/ssl/kube-apiserver.pem \
 --tls-private-key-file=/etc/kubernetes/ssl/kube-apiserver-key.pem \
 --client-ca-file=/etc/kubernetes/ssl/ca.pem \
 --kubelet-client-certificate=/etc/kubernetes/ssl/kube-apiserver.pem \
 --kubelet-client-key=/etc/kubernetes/ssl/kube-apiserver-key.pem \
 --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \
 --service-account-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \
 --service-account-issuer=https://kubernetes.default.svc.cluster.local \
 --etcd-cafile=/etc/etcd/ssl/ca.pem \
 --etcd-certfile=/etc/etcd/ssl/etcd.pem \
 --etcd-keyfile=/etc/etcd/ssl/etcd-key.pem \
 --etcd-servers=https://10.0.0.20:2379,https://10.0.0.21:2379,https://10.0.0.22:2379 \
 --enable-swagger-ui=true \
 --allow-privileged=true \
 --apiserver-count=3 \
 --audit-log-maxage=30 \
 --audit-log-maxbackup=3 \
 --audit-log-maxsize=100 \
 --audit-log-path=/var/log/kube-apiserver-audit.log \
 --event-ttl=1h \
 --alsologtostderr=true \
 --logtostderr=false \
 --log-dir=/var/log/kubernetes \
 --v=4"
EOF
```

#### 3.4、kube-apiserver.service

```sh
cat > /usr/lib/systemd/system/kube-apiserver.service << "EOF"
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=etcd.service
Wants=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/kube-apiserver.conf
ExecStart=/usr/local/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /usr/lib/systemd/system/kube-apiserver.service $i:/usr/lib/systemd/system/;done
```

#### 3.5、start kube-apiserver.service

```sh
systemctl daemon-reload
systemctl enable --now kube-apiserver.service
systemctl status kube-apiserver.service
---
# check
curl --insecure https://10.0.0.20:6443
---
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
```

### 4、kubectl

#### 4.1、admin certificate

```sh
cat > admin-csr.json << "EOF"
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "system:masters",
      "OU": "system"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
cp admin*.pem /etc/kubernetes/ssl/
---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/ssl/admin*.pem $i:/etc/kubernetes/ssl/;done 
```

#### 4.2、admin.config

```sh
# 1、设置集群参数
kubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.0.0.25:6444 --kubeconfig=admin.config

# 2、设置客户端认证参数
kubectl config set-credentials kubernetes-admin --client-certificate=admin.pem --client-key=admin-key.pem --embed-certs=true --kubeconfig=admin.config

# 3、设置上下文参数
kubectl config set-context kubernetes --cluster=kubernetes --user=kubernetes-admin --kubeconfig=admin.config

# 4、设置当前上下文
kubectl config use-context kubernetes --kubeconfig=admin.config
```

#### 4.3、kubernetes-kubelet api

```sh
kubectl create clusterrolebinding kube-apiserver:kubelet-apiserver --clusterrole=system.kubelet-api-admin --user kubernetes
kubectl create clusterrolebinding kubernetes --clusterrole=cluster-admin --user=kubernetes
```

#### 4.4、send to other

```sh
cp ~/work/admin.config /etc/kubernetes
mkdir -p $HOME/.kube
cp -i /etc/kubernetes/admin.config $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config

for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/admin.config $i:/etc/kubernetes/;done

echo "export KUBECONFIG=/etc/kubernetes/admin.config" >> /etc/profile
source /etc/profile
```

#### 4.5、kubectl(bash-completion)

```sh
source <(kubectl completion bash)
echo "source <(kubectl completion bash)" >> /etc/profile
source /etc/profile
```

#### 4.6、verify kubectl

```sh
kubectl cluster-info
---
{Kubernetes control plane is running at https://10.0.0.20:6443}
---
kubectl get componentstatuses
---
NAME                 STATUS      MESSAGE                                                                                        ERROR
scheduler            Unhealthy   Get "https://127.0.0.1:10259/healthz": dial tcp 127.0.0.1:10259: connect: connection refused   
controller-manager   Unhealthy   Get "https://127.0.0.1:10257/healthz": dial tcp 127.0.0.1:10257: connect: connection refused   
etcd-0               Healthy     {"health":"true","reason":""}                                           
etcd-1               Healthy     {"health":"true","reason":""}                                           
etcd-2               Healthy     {"health":"true","reason":""}                                           
---
kubectl get all --all-namespaces
---
NAMESPACE   NAME                 TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
default     service/kubernetes   ClusterIP   10.96.0.1   <none>        443/TCP   56m
```

### 5、kube-controller-manager

#### 5.1、kube-controller-manager certificate

```sh
cat > kube-controller-manager-csr.json << "EOF"
{
  "CN": "system:kube-controller-manager",
  "hosts": [
    "127.0.0.1",
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.25"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "system:kube-controller-manager",
      "OU": "Kubernetes"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
cp kube-controller-manager*.pem /etc/kubernetes/ssl/
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/ssl/kube-controller-manager*.pem $i:/etc/kubernetes/ssl/;done
```

#### 5.2、kube-controller-manager.kubeconfig

```sh
# 1、设置集群参数
kubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.0.0.25:6444 --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig

# 2、设置客户端认证参数
kubectl config set-credentials system:kube-controller-manager --client-certificate=kube-controller-manager.pem --client-key=kube-controller-manager-key.pem --embed-certs=true --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig

# 3、设置上下文参数
kubectl config set-context system:kube-controller-manager --cluster=kubernetes --user=system:kube-controller-manager --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig

# 4、设置当前上下文
kubectl config use-context system:kube-controller-manager --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig
```

#### 5.3、kube-controller-manager.conf

```sh
cat > /etc/kubernetes/kube-controller-manager.conf << "EOF"
KUBE_CONTROLLER_MANAGER_OPTS="--v=2 \
  --secure-port=10257 \
  --bind-address=127.0.0.1 \
  --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \
  --service-cluster-ip-range=10.96.0.0/16 \
  --cluster-name=kubernetes \
  --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \
  --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --allocate-node-cidrs=true \
  --cluster-cidr=10.244.0.0/16 \
  --experimental-cluster-signing-duration=87600h \
  --root-ca-file=/etc/kubernetes/ssl/ca.pem \
  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --leader-elect=true \
  --feature-gates=RotateKubeletServerCertificate=true \
  --controllers=*,bootstrapsigner,tokencleaner \
  --horizontal-pod-autoscaler-sync-period=10s \
  --tls-cert-file=/etc/kubernetes/ssl/kube-controller-manager.pem \
  --tls-private-key-file=/etc/kubernetes/ssl/kube-controller-manager-key.pem \
  --use-service-account-credentials=true"
EOF
  ---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/kube-controller-manager* $i:/etc/kubernetes/;done
```

#### 5.4、kube-controller-manager.service

```sh
cat > /usr/lib/systemd/system/kube-controller-manager.service << "EOF"
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/kube-controller-manager.conf
ExecStart=/usr/local/bin/kube-controller-manager $KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /usr/lib/systemd/system/kube-controller-manager.service $i:/usr/lib/systemd/system/;done
```

#### 5.5、start kube-controller-manager.service

```sh
systemctl daemon-reload
systemctl enable --now kube-controller-manager.service
systemctl status kube-controller-manager.service
```

### 6、kube-scheduler

#### 6.1、kube-scheduler certificate

```sh
cat > kube-scheduler-csr.json << "EOF"
{
  "CN": "system:kube-scheduler",
  "hosts": [
    "127.0.0.1",
    "10.0.0.20",
    "10.0.0.21",
    "10.0.0.22",
    "10.0.0.25"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "system:kube-scheduler",
      "OU": "system"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
cp kube-scheduler*.pem /etc/kubernetes/ssl/
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/ssl/kube-scheduler*.pem $i:/etc/kubernetes/ssl/;done
```

#### 6.2、kube-scheduler.kubeconfig

```sh
# 1、设置集群参数
kubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.0.0.25:6444 --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig

# 2、设置客户端认证参数
kubectl config set-credentials system:kube-scheduler --client-certificate=kube-scheduler.pem --client-key=kube-scheduler-key.pem --embed-certs=true --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig

# 3、设置上下文参数
kubectl config set-context system:kube-scheduler --cluster=kubernetes --user=system:kube-scheduler --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig

# 4、设置当前上下文
kubectl config use-context system:kube-scheduler --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig
```

#### 6.3、kube-scheduler.conf

```sh
cat > /etc/kubernetes/kube-scheduler.conf << "EOF"
KUBE_SCHEDULER_OPTS="--address=127.0.0.1 \
  --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \
  --leader-elect=true \
  --alsologtostderr=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes \
  --v=2"
EOF
---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /etc/kubernetes/kube-scheduler* $i:/etc/kubernetes/;done
```

#### 6.4、kube-scheduler.service

```sh
cat > /usr/lib/systemd/system/kube-scheduler.service << "EOF"
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/kube-scheduler.conf
ExecStart=/usr/local/bin/kube-scheduler $KUBE_SCHEDULER_OPTS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
---
for i in `cat ~/MasterNodes.txt`;do echo $i;scp /usr/lib/systemd/system/kube-scheduler.service $i:/usr/lib/systemd/system/;done
```

#### 6.5、start kube-scheduler.service

```sh
systemctl daemon-reload
systemctl enable --now kube-scheduler.service
systemctl status kube-scheduler.service
```

## 四、Node

### 1、kubelet

#### 1.1、BOOTSTRAP_TOKEN

```sh
BOOTSTRAP_TOKEN=$(awk -F "," '{print $1}' /etc/kubernetes/token.csv)
```

#### 1.2、kubelet-bootstrap.kubeconfig

```sh
# 1、设置集群参数
kubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.0.0.25:6444 --kubeconfig=/root/work/kubelet-bootstrap.kubeconfig

# 2、设置客户端认证参数
kubectl config set-credentials kubelet-bootstrap --token=${BOOTSTRAP_TOKEN} --kubeconfig=/root/work/kubelet-bootstrap.kubeconfig

# 3、设置上下文参数
kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap --kubeconfig=/root/work/kubelet-bootstrap.kubeconfig

# 4、设置当前上下文
kubectl config use-context default --kubeconfig=/root/work/kubelet-bootstrap.kubeconfig

# 5、创建clusterrolebinding
kubectl delete clusterrolebinding kubelet-bootstrap
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap
kubectl create clusterrolebinding cluster-system-anonymous --clusterrole=cluster-admin --user=kubelet-bootstrap
```

#### 1.3、kubelet.json

```sh
cat > ~/work/kubelet.json << "EOF"
{
 "kind": "KubeletConfiguration",
 "apiVersion": "kubelet.config.k8s.io/v1beta1",
 "authentication": {
   "x509": {
     "clientCAFile": "/etc/kubernetes/ssl/ca.pem"
   },
   "webhook": {
     "enabled": true,
     "cacheTTL": "2m0s"
   },
   "anonymous": {
     "enabled": false
   }
 },
 "authorization": {
   "mode": "Webhook",
   "webhook": {
     "cacheAuthorizedTTL": "5m0s",
     "cacheUnauthorizedTTL": "30s"
   }
 },
 "address": "10.0.0.23",
 "port": 10250,
 "readOnlyPort": 10255,
 "cgroupDriver": "systemd",
 "hairpinMode": "promiscuous-bridge",
 "serializeImagePulls": false,
 "clusterDomain": "cluster.local.",
 "clusterDNS": ["10.96.0.2"]
}
EOF
```

#### 1.4、kubelet.service

```sh
cat > ~/work/kubelet.service <<"EOF"
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=containerd.service
Requires=containerd.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/local/bin/kubelet \
 --container-runtime=remote \
 --container-runtime-endpoint=unix:///run/containerd/containerd.sock
 --bootstrap-kubeconfig=/etc/kubernetes/kubelet-bootstrap.kubeconfig \
 --cert-dir=/etc/kubernetes/ssl \
 --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
 --config=/etc/kubernetes/kubelet.json \
 --pod-infra-container-image=registry.aliyuncs.com/google_containers/pause:3.2 \
 --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
---
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kubelet.json ~/work/kubelet-bootstrap.kubeconfig $i:/etc/kubernetes;done
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kubelet.service $i:/usr/lib/systemd/system;done
for i in `cat ~/WorkNodes.txt`;do echo $i;scp /etc/kubernetes/ssl/ca.pem $i:/etc/kubernetes/ssl/;done
```

#### 1.5、start kubelet.services

```sh
mkdir -p /var/lib/kubelet
systemctl daemon-reload
systemctl enable --now kubelet.service
systemctl status kubelet.service
```

#### 1.6、Approve Nodes

```sh
kubectl get csr |grep node |awk '{print$1,$6}'

"+---                                                  |     ---+"
  node-csr-BV7RZ1Mc1RFkWhH9jzJH8h8on_dRMB3an_7FgBUwWhk   Pending
  node-csr-wZOI__ACKylv7DlEPRK8iMg3_sYyBErjbGjxkMkRyPo   Pending
"+---                                                  |     ---+"

kubectl certificate approve node-csr-csr-BV7RZ1Mc1RFkWhH9jzJH8h8on_dRMB3an_7FgBUwWhk node-csr-wZOI__ACKylv7DlEPRK8iMg3_sYyBErjbGjxkMkRyPo

kubectl get nodes
NAME         STATUS   ROLES    AGE    VERSION
k8s-node01   Ready    <none>   118m   v1.23.5
k8s-node02   Ready    <none>   118m   v1.23.5
```

### 2、kube-pproxy

#### 2.1、kube-proxy certificate

```sh
cat > kube-proxy-csr.json << "EOF"
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Shanghai",
      "L": "Shanghai",
      "O": "k8s",
      "OU": "system"
    }
  ]
}
EOF
---
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
cp kube-proxy*.pem /etc/kubernetes/ssl/
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kube-proxy*.pem $i:/etc/kubernetes/ssl/;done
```

#### 2.2、kube-proxy.kubeconfig

```sh
# 1、设置集群参数
kubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.0.0.25:6444 --kubeconfig=/root/work/kube-proxy.kubeconfig

# 2、设置客户端认证参数
kubectl config set-credentials kube-proxy --client-certificate=kube-proxy.pem --client-key=kube-proxy-key.pem --embed-certs=true --kubeconfig=/root/work/kube-proxy.kubeconfig

# 3、设置上下文参数
kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=/root/work/kube-proxy.kubeconfig

# 4、设置当前上下文
kubectl config use-context default --kubeconfig=/root/work/kube-proxy.kubeconfig
```

#### 2.3、kube-proxy.yaml

```sh
# 以下bindAddress均为宿主机ip,clusterCIDR为宿主机网段
---
cat > ~/work/kube-proxy.yaml << "EOF"
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 10.0.0.23
clientConnection:
  kubeconfig: /etc/kubernetes/kube-proxy.kubeconfig
clusterCIDR: 10.244.0.0/24
healthzBindAddress: 10.0.0.23:10256
kind: KubeProxyConfiguration
metricsBindAddress: 10.0.0.23:10249
mode: "ipvs"
EOF
---
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kube-proxy.yaml ~/work/kube-proxy.kubeconfig $i:/etc/kubernetes/;done
```

#### 2.4、kube-proxy.service

```sh
cat > ~/work/kube-proxy.service << "EOF"
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/usr/local/bin/kube-proxy \
 --config=/etc/kubernetes/kube-proxy.yaml \
 --alsologtostderr=true \
 --logtostderr=false \
 --log-dir=/var/log/kubernetes \
 --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
---
for i in `cat ~/WorkNodes.txt`;do echo $i;scp ~/work/kube-proxy.service $i:/usr/lib/systemd/system;done
```

#### 2.5、start kube-proxy.services

```sh
mkdir -p /var/lib/kube-proxy
systemctl daemon-reload
systemctl enable --now kube-proxy.service
systemctl status kube-proxy.service
```

## 五、network

### 1、calico

```sh
wget https://docs.projectcalico.org/manifests/calico.yaml
kubectl apply -f calico.yaml
```

### 2、coredns

#### 2.1、resolv.conf

```sh
mv /etc/resolv.conf  /etc/resolv.conf.bak
ln -s /run/systemd/resolve/resolv.conf /etc/
systemctl restart systemd-resolved.service && systemctl enable systemd-resolved.service
```

#### 2.2、coredns.yaml

```sh
apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
rules:
  - apiGroups:
    - ""
    resources:
    - endpoints
    - services
    - pods
    - namespaces
    verbs:
    - list
    - watch
  - apiGroups:
    - discovery.k8s.io
    resources:
    - endpointslices
    verbs:
    - list
    - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
          lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        forward . /etc/resolv.conf {
          max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/name: "CoreDNS"
spec:
  # replicas: not specified here:
  # 1. Default is 1.
  # 2. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      nodeSelector:
        kubernetes.io/os: linux
      affinity:
         podAntiAffinity:
           preferredDuringSchedulingIgnoredDuringExecution:
           - weight: 100
             podAffinityTerm:
               labelSelector:
                 matchExpressions:
                   - key: k8s-app
                     operator: In
                     values: ["kube-dns"]
               topologyKey: kubernetes.io/hostname
      containers:
      - name: coredns
        image: coredns/coredns:1.8.4
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /ready
            port: 8181
            scheme: HTTP
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
---
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.96.0.2
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
```

#### 2.3、install

```sh
kubectl apply -f coredns.yaml
```

