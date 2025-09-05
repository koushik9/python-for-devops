# 📊 ULTIMATE DEVOPS INTERVIEW CHEAT SHEET
## Python + DSA + AWS + DevOps + Networking + Terraform

---

## 📚 TABLE OF CONTENTS
1. [🐍 Complete Python Data Structures](#complete-python-data-structures)
2. [🧠 DSA Algorithms with Time Complexity](#dsa-algorithms-with-time-complexity) 
3. [📚 Essential Python Libraries for DevOps](#essential-python-libraries-for-devops)
4. [🏗️ Terraform Concepts](#terraform-concepts)
5. [☁️ AWS Services Deep Dive](#aws-services-deep-dive)
6. [🌐 Networking & Security](#networking--security)
7. [🎯 25 Real-World DevOps Examples](#25-real-world-devops-examples)
8. [⚡ 10 AWS Boto3 Examples](#10-aws-boto3-examples)
9. [🚀 15 Real-Time Production Examples](#15-real-time-production-examples)
10. [📋 Quick Reference Cards](#quick-reference-cards)

---

## 🐍 COMPLETE PYTHON DATA STRUCTURES

| **Concept** | **Syntax** | **Example** | **Real DevOps Use** | **Time Complexity** |
|-------------|------------|-------------|---------------------|---------------------|
| **List** | `[]` | `servers = ['web-01', 'db-01']` | Store server lists, process logs | O(1) append, O(n) insert |
| **Array (NumPy)** | `np.array()` | `cpu_usage = np.array([80, 90, 75])` | Process metrics data | O(1) access |
| **Tuple** | `()` | `config = ('prod', 'us-west-2', '1.27')` | Immutable cluster configs | O(1) access |
| **Set** | `{}` | `unique_ips = {'192.168.1.1', '192.168.1.2'}` | Remove duplicate IPs | O(1) lookup |
| **Dictionary** | `{}` | `server_info = {'ip': '192.168.1.1', 'port': 8080}` | Store server metadata | O(1) avg access |
| **String** | `""` | `log_line = "ERROR: Connection failed"` | Parse log files | O(n) operations |
| **Regex** | `re.search(pattern, text)` | `re.search(r'\d+\.\d+\.\d+\.\d+', log)` | Extract IP addresses | O(n) |
| **List Comprehension** | `[x for x in list if condition]` | `[s for s in servers if s.startswith('web')]` | Filter servers | O(n) |
| **Dict Comprehension** | `{k: v for k, v in dict.items()}` | `{k: len(v) for k, v in logs.items()}` | Count log entries | O(n) |
| **Generator** | `(x for x in range(10))` | `(line for line in open('log.txt'))` | Process large files | Memory efficient |
| **DefaultDict** | `defaultdict(list)` | `servers_by_region = defaultdict(list)` | Group servers by region | O(1) access |
| **Counter** | `Counter(list)` | `Counter(['error', 'info', 'error'])` | Count log levels | O(n) |
| **Deque** | `deque([])` | `task_queue = deque(['deploy', 'test'])` | Task queues | O(1) both ends |
| **OrderedDict** | `OrderedDict()` | `deployment_order = OrderedDict()` | Maintain deployment order | O(1) access |
| **NamedTuple** | `namedtuple('Server', ['name', 'ip'])` | `Server('web-01', '10.0.1.1')` | Structured server data | O(1) access |

---

## 🧠 DSA ALGORITHMS WITH TIME COMPLEXITY

| **Algorithm** | **Code Template** | **Time Complexity** | **Space** | **DevOps Use Case** |
|---------------|-------------------|---------------------|-----------|---------------------|
| **Binary Search** | `while left <= right: mid = (left + right) // 2` | O(log n) | O(1) | Find server in sorted list |
| **Quick Sort** | `pivot = arr[mid]; left = [x for x < pivot]` | O(n log n) avg | O(log n) | Sort server metrics |
| **Merge Sort** | `merge(left_half, right_half)` | O(n log n) | O(n) | Stable sorting of logs |
| **Heap Sort** | `heapq.heappush(heap, item)` | O(n log n) | O(1) | Priority task queue |
| **DFS (Recursive)** | `visited.add(node); dfs(neighbor)` | O(V + E) | O(h) | Service dependency tree |
| **BFS (Queue)** | `queue.append(start); queue.popleft()` | O(V + E) | O(w) | Network shortest path |
| **Dijkstra** | `heapq.heappop(pq); update distances` | O(E log V) | O(V) | Find fastest deployment path |
| **Hash Table** | `hash_map[key] = value` | O(1) avg | O(n) | Cache lookup, config store |
| **Two Pointers** | `left = 0; right = len-1` | O(n) | O(1) | Find server pairs |
| **Sliding Window** | `window = deque(); window.append(item)` | O(n) | O(k) | Monitor metrics window |
| **Union Find** | `parent[find(x)] = find(y)` | O(α(n)) | O(n) | Network connectivity |
| **Trie** | `node.children[char] = TrieNode()` | O(m) | O(n*m) | Auto-complete server names |

### **Algorithm Visualization Examples**

#### **Binary Search - Server Lookup**
```
Sorted Servers: [api-01, db-01, web-01, web-02, web-03]
Target: "web-01"

Step 1: left=0, right=4, mid=2 → servers[2]="web-01" ✅ FOUND!
```

#### **DFS - Service Dependencies**
```
Load Balancer
├── Web-01 
│   ├── API-01
│   │   ├── DB-01
│   │   └── Cache-01
│   └── Queue-01
└── Web-02
    └── API-01 (already visited)

DFS Order: LB → Web-01 → API-01 → DB-01 → Cache-01 → Queue-01 → Web-02
```

---

## 📚 ESSENTIAL PYTHON LIBRARIES FOR DEVOPS

| **Library** | **Import Statement** | **Key Functions** | **DevOps Use Case** | **Example** |
|-------------|---------------------|-------------------|---------------------|-------------|
| **boto3** | `import boto3` | `client(), resource()` | AWS API interactions | `ec2 = boto3.client('ec2')` |
| **requests** | `import requests` | `get(), post(), put()` | HTTP API calls, webhooks | `requests.get('https://api.github.com')` |
| **paramiko** | `import paramiko` | `SSHClient(), connect()` | SSH connections, file transfer | `ssh.connect('server', username='user')` |
| **fabric** | `from fabric import Connection` | `run(), put(), get()` | Remote command execution | `c.run('sudo systemctl restart nginx')` |
| **ansible** | `import ansible` | `playbook_run()` | Configuration management | Execute Ansible playbooks |
| **docker** | `import docker` | `containers.run()` | Container management | `docker.containers.run('nginx')` |
| **kubernetes** | `from kubernetes import client` | `list_pod_for_all_namespaces()` | K8s cluster management | `v1.list_pod_for_all_namespaces()` |
| **psutil** | `import psutil` | `cpu_percent(), virtual_memory()` | System monitoring | `psutil.cpu_percent(interval=1)` |
| **subprocess** | `import subprocess` | `run(), Popen()` | Execute shell commands | `subprocess.run(['ls', '-la'])` |
| **logging** | `import logging` | `info(), error(), warning()` | Application logging | `logging.error('Deployment failed')` |
| **json** | `import json` | `loads(), dumps()` | Parse API responses | `data = json.loads(response.text)` |
| **yaml** | `import yaml` | `load(), dump()` | Config files, K8s manifests | `config = yaml.load(open('config.yml'))` |
| **pandas** | `import pandas as pd` | `read_csv(), DataFrame()` | Data analysis, metrics | `df = pd.read_csv('metrics.csv')` |
| **schedule** | `import schedule` | `every().minutes.do()` | Task scheduling | `schedule.every(5).minutes.do(backup)` |
| **click** | `import click` | `@click.command()` | CLI applications | `@click.command() def deploy():` |
| **jinja2** | `from jinja2 import Template` | `render()` | Template rendering | `template.render(servers=server_list)` |
| **cryptography** | `from cryptography.fernet import Fernet` | `encrypt(), decrypt()` | Secret management | `fernet.encrypt(password.encode())` |
| **redis** | `import redis` | `get(), set(), hget()` | Caching, session storage | `r.set('session:123', user_data)` |
| **pymongo** | `import pymongo` | `find(), insert_one()` | MongoDB operations | `db.servers.find({'status': 'active'})` |
| **sqlalchemy** | `from sqlalchemy import create_engine` | `execute()` | Database ORM | `engine.execute('SELECT * FROM servers')` |

---

## 🏗️ TERRAFORM CONCEPTS

| **Concept** | **Syntax** | **Example** | **Use Case** | **Best Practice** |
|-------------|------------|-------------|--------------|-------------------|
| **Provider** | `provider "aws" {}` | `provider "aws" { region = "us-west-2" }` | Cloud platform connection | Pin provider versions |
| **Resource** | `resource "type" "name" {}` | `resource "aws_instance" "web" {}` | Create infrastructure | Use descriptive names |
| **Data Source** | `data "type" "name" {}` | `data "aws_ami" "latest" {}` | Reference existing resources | Prefer data over hardcoding |
| **Variable** | `variable "name" {}` | `variable "instance_type" { default = "t3.micro" }` | Parameterize configurations | Add descriptions |
| **Output** | `output "name" {}` | `output "instance_ip" { value = aws_instance.web.public_ip }` | Return values | Output important info |
| **Local** | `locals {}` | `locals { common_tags = { Environment = "prod" } }` | Computed values | Reduce repetition |
| **Module** | `module "name" {}` | `module "vpc" { source = "./modules/vpc" }` | Reusable components | Keep modules focused |
| **Backend** | `backend "s3" {}` | `backend "s3" { bucket = "tf-state" }` | Remote state storage | Always use remote state |
| **Workspace** | `terraform workspace new prod` | `terraform workspace select staging` | Environment isolation | Use for environments |
| **Count** | `count = 3` | `resource "aws_instance" "web" { count = 3 }` | Create multiple resources | Use for identical resources |
| **For Each** | `for_each = var.servers` | `for_each = toset(var.availability_zones)` | Iterate over collections | Better than count |
| **Conditional** | `count = condition ? 1 : 0` | `count = var.create_database ? 1 : 0` | Conditional resource creation | Clean conditional logic |

### **Terraform Workflow Diagram**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ terraform   │───▶│ terraform   │───▶│ terraform   │───▶│ terraform   │
│ init        │    │ plan        │    │ apply       │    │ destroy     │
│             │    │             │    │             │    │             │
│ • Download  │    │ • Preview   │    │ • Execute   │    │ • Remove    │
│   providers │    │   changes   │    │   changes   │    │   resources │
│ • Initialize│    │ • Validate  │    │ • Update    │    │ • Clean up  │
│   backend   │    │   syntax    │    │   state     │    │   state     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### **Terraform State Management**
```
Remote State Architecture:

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Developer 1   │    │   Developer 2   │    │   CI/CD Pipeline│
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                         ┌───────▼───────┐
                         │   S3 Bucket   │
                         │  (State File) │
                         └───────┬───────┘
                                 │
                         ┌───────▼───────┐
                         │ DynamoDB Table│
                         │ (State Lock)  │
                         └───────────────┘
```

---

## 🎯 25 REAL-WORLD DEVOPS EXAMPLES

| **#** | **Example** | **Technology** | **Code/Command** | **Use Case** |
|-------|-------------|----------------|------------------|--------------|
| **1** | **Health Check Monitor** | Python + Requests | `requests.get(f'{url}/health', timeout=5)` | Monitor service availability |
| **2** | **Log Parser & Alerter** | Python + Regex | `re.findall(r'ERROR.*', log_content)` | Parse logs for errors |
| **3** | **Server Resource Monitor** | Python + psutil | `psutil.cpu_percent(), psutil.virtual_memory()` | Track CPU/memory usage |
| **4** | **SSL Certificate Checker** | Python + ssl | `ssl.create_default_context().check_hostname` | Monitor cert expiration |
| **5** | **Docker Container Manager** | Python + docker | `client.containers.run('nginx', detach=True)` | Automate container lifecycle |
| **6** | **K8s Pod Auto-Scaler** | Python + kubernetes | `apps_v1.patch_namespaced_deployment_scale()` | Scale pods based on metrics |
| **7** | **Database Backup Verifier** | Python + subprocess | `subprocess.run(['pg_dump', '-h', host])` | Verify backup integrity |
| **8** | **Network Connectivity Test** | Python + socket | `socket.create_connection((host, port), timeout=3)` | Test network connectivity |
| **9** | **Security Compliance Scanner** | Python + nmap | `nm.scan(host, '22-443')` | Scan for open ports |
| **10** | **Cost Optimization Analyzer** | Python + boto3 | `ec2.describe_instances()` | Find unused resources |
| **11** | **Disaster Recovery Tester** | Python + boto3 | `rds.create_db_snapshot()` | Test backup/restore |
| **12** | **Config Drift Detector** | Python + difflib | `difflib.unified_diff(current, expected)` | Detect configuration changes |
| **13** | **API Rate Limiter** | Python + redis | `redis.incr(f'rate_limit:{user_id}')` | Enforce API rate limits |
| **14** | **Service Mesh Monitor** | Python + prometheus | `requests.get('/metrics')` | Monitor microservices |
| **15** | **IaC Validator** | Python + terraform | `subprocess.run(['terraform', 'validate'])` | Validate Terraform code |
| **16** | **Multi-Cloud Resource Manager** | Python + boto3/azure | `ec2.describe_instances(), compute.instances()` | Manage across clouds |
| **17** | **Incident Response Automation** | Python + slack API | `slack.chat_postMessage(channel, text)` | Automate incident alerts |
| **18** | **Performance Regression Test** | Python + locust | `locust -f loadtest.py --host=https://api.com` | Load testing |
| **19** | **Data Pipeline Monitor** | Python + airflow | `airflow.models.DagRun.find()` | Monitor data workflows |
| **20** | **Secret Rotation Automation** | Python + vault | `client.secrets.kv.v2.create_or_update_secret()` | Rotate secrets automatically |
| **21** | **Load Balancer Health Check** | Python + requests | Check ALB/F5 backend health | Ensure LB backends healthy |
| **22** | **Metrics Aggregator** | Python + prometheus | `prometheus_client.Counter()` | Collect custom metrics |
| **23** | **Auto Documentation Generator** | Python + jinja2 | `template.render(servers=inventory)` | Generate docs from code |
| **24** | **Compliance Reporter** | Python + boto3 | Check security groups, encryption | Generate compliance reports |
| **25** | **Chaos Engineering Tool** | Python + random | `random.choice(instances).terminate()` | Test system resilience |

---

## ⚡ 10 AWS BOTO3 EXAMPLES

| **#** | **Service** | **Operation** | **Code Example** | **Real Use Case** |
|-------|-------------|---------------|------------------|-------------------|
| **1** | **EC2** | List Instances | `ec2.describe_instances()` | Inventory management |
| **2** | **RDS** | Create DB Instance | `rds.create_db_instance(DBInstanceIdentifier='prod-db')` | Database provisioning |
| **3** | **S3** | Upload with Encryption | `s3.put_object(Bucket='my-bucket', Key='file.txt', ServerSideEncryption='AES256')` | Secure file storage |
| **4** | **Lambda** | Deploy Function | `lambda_client.create_function(FunctionName='processor', Runtime='python3.9')` | Serverless deployment |
| **5** | **CloudWatch** | Create Alarm | `cloudwatch.put_metric_alarm(AlarmName='HighCPU', MetricName='CPUUtilization')` | Infrastructure monitoring |
| **6** | **EKS** | Create Cluster | `eks.create_cluster(name='prod-cluster', version='1.28')` | Kubernetes cluster setup |
| **7** | **DynamoDB** | Batch Write | `dynamodb.batch_write_item(RequestItems={'table': [{'PutRequest': {'Item': data}}]})` | Bulk data operations |
| **8** | **SNS** | Send Notifications | `sns.publish(TopicArn='arn:aws:sns:us-west-2:123:alerts', Message='Alert!')` | Alert notifications |
| **9** | **VPC** | Create Security Group | `ec2.create_security_group(GroupName='web-sg', Description='Web servers')` | Network security |
| **10** | **IAM** | Create Role | `iam.create_role(RoleName='LambdaRole', AssumeRolePolicyDocument=policy)` | Access management |

---

## 🚀 15 REAL-TIME PRODUCTION EXAMPLES

| **#** | **Environment** | **Example** | **Technologies** | **Implementation** | **Business Impact** |
|-------|----------------|-------------|------------------|-------------------|-------------------|
| **1** | **AWS + EKS** | **Auto-Scaling Microservices** | EKS, ALB, HPA, Prometheus | `kubectl apply -f hpa.yaml` | Handle 10x traffic spikes |
| **2** | **Multi-Region DR** | **Database Failover System** | RDS Multi-AZ, Route53, Lambda | Cross-region automated failover | 99.99% uptime SLA |
| **3** | **GitLab CI/CD** | **Blue-Green Deployment** | GitLab, Docker, K8s, Helm | Zero-downtime deployments | Reduce deployment risk |
| **4** | **Terraform + AWS** | **Infrastructure Automation** | Terraform, AWS, GitLab CI | `terraform apply` automation | 90% faster provisioning |
| **5** | **F5 + ALB** | **Hybrid Load Balancing** | F5 BIG-IP, AWS ALB, SSL offload | Traffic distribution | High availability |
| **6** | **Imperva WAF** | **Security Automation** | Imperva WAF, Custom rules, API | Block attacks automatically | 99% threat reduction |
| **7** | **Redis Cluster** | **Session Management** | Redis Cluster, ElastiCache | Distributed session store | Scale to millions users |
| **8** | **MSK + Lambda** | **Real-time Data Pipeline** | MSK, Lambda, DynamoDB | Stream processing | Real-time analytics |
| **9** | **Docker Swarm** | **Container Orchestration** | Docker Swarm, Portainer | Multi-host container management | Resource optimization |
| **10** | **Linux Automation** | **System Hardening** | Ansible, Linux, Security policies | Automated security compliance | SOC2 compliance |
| **11** | **Network Segmentation** | **VPC Architecture** | VPC, Subnets, NACLs, Security Groups | Micro-segmentation | Enhanced security |
| **12** | **Database Optimization** | **RDS Performance Tuning** | RDS, CloudWatch, Performance Insights | Query optimization | 50% faster queries |
| **13** | **Monitoring Stack** | **Observability Platform** | Prometheus, Grafana, ELK, Jaeger | Full-stack monitoring | MTTR reduction |
| **14** | **Secret Management** | **Vault Integration** | HashiCorp Vault, K8s, Cert-Manager | Automated secret rotation | Security compliance |
| **15** | **Cost Optimization** | **Resource Right-Sizing** | AWS Cost Explorer, Lambda, Slack | Automated cost alerts | 30% cost reduction |

### **Architecture Diagrams**

#### **High-Availability Web Application**
```
                    ┌─────────────────┐
                    │   CloudFront    │  ◄─── Global CDN
                    │      (CDN)      │
                    └─────────┬───────┘
                              │
                    ┌─────────▼───────┐
                    │   Route53 DNS   │  ◄─── Health Checks
                    │  (Failover)     │
                    └─────────┬───────┘
                              │
                    ┌─────────▼───────┐
                    │  ALB (Layer 7)  │  ◄─── SSL Termination
                    │ us-west-2a/2b   │       Path-based Routing
                    └─────────┬───────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
        ┌───────▼───────┐ ┌───▼────┐ ┌─────▼─────┐
        │  EKS Cluster  │ │  EKS   │ │    EKS    │
        │   (Web Apps)  │ │(APIs)  │ │(Workers)  │
        │  AZ-2a        │ │ AZ-2b  │ │  AZ-2c    │
        └───────┬───────┘ └───┬────┘ └─────┬─────┘
                │             │            │
        ┌───────▼───────┐ ┌───▼────┐ ┌─────▼─────┐
        │ RDS Primary   │ │  Read  │ │ElastiCache│
        │   (Multi-AZ)  │ │Replica │ │  (Redis)  │
        └───────────────┘ └────────┘ └───────────┘
```

#### **CI/CD Pipeline with Security**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   GitLab    │───▶│   Build     │───▶│   Security  │───▶│   Deploy    │
│   (Source)  │    │   (Docker)  │    │   (SAST)    │    │   (K8s)     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Code Review │    │ Unit Tests  │    │ Vulnerability│    │ Blue-Green  │
│ Merge Gate  │    │ Coverage    │    │ Scanning    │    │ Deployment  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

---

## ☁️ AWS SERVICES DEEP DIVE

| **Service** | **Type** | **Key Features** | **Use Cases** | **Pricing Model** | **Interview Focus** |
|-------------|----------|------------------|---------------|-------------------|---------------------|
| **EC2** | Compute | Auto Scaling, Multiple Instance Types | Web servers, batch processing | On-demand, Reserved, Spot | Instance types, pricing |
| **RDS** | Database | Multi-AZ, Read Replicas, Automated backups | Relational databases | Instance hours + storage | Multi-AZ vs Read Replicas |
| **DynamoDB** | NoSQL Database | Serverless, Global Tables, DAX | High-throughput apps | Pay per request/capacity | Partition keys, GSI |
| **ElastiCache** | In-Memory Cache | Redis/Memcached, Clustering | Session store, database cache | Node hours | Redis vs Memcached |
| **S3** | Object Storage | 11 9's durability, Lifecycle policies | Static websites, backups | Storage + requests | Storage classes |
| **EKS** | Container Orchestration | Managed Kubernetes, Fargate | Microservices, containerized apps | Control plane + worker nodes | K8s concepts |
| **Lambda** | Serverless Compute | Event-driven, Auto-scaling | API backends, data processing | Requests + duration | Cold starts, limits |
| **VPC** | Networking | Subnets, Security Groups, NACLs | Network isolation | No additional cost | Security Groups vs NACLs |
| **ALB/NLB** | Load Balancer | Layer 7/4, SSL termination | Traffic distribution | Load balancer hours + LCUs | ALB vs NLB differences |
| **CloudWatch** | Monitoring | Metrics, Logs, Alarms | Infrastructure monitoring | Metrics + log ingestion | Custom metrics |

---

## 🌐 NETWORKING & SECURITY

| **Concept** | **Technology** | **Configuration** | **Security Implications** | **DevOps Use** |
|-------------|----------------|-------------------|---------------------------|----------------|
| **VPC Architecture** | AWS VPC | Public/Private Subnets, NAT Gateway | Network isolation | Multi-tier applications |
| **Security Groups** | AWS/F5 | Allow rules, stateful | Instance-level firewall | Application security |
| **Network ACLs** | AWS | Allow/Deny rules, stateless | Subnet-level firewall | Defense in depth |
| **F5 Virtual Server** | F5 BIG-IP | VIP + Pool + Profile | SSL offload, DDoS protection | High-performance LB |
| **Imperva WAF** | Web Security | OWASP rules, custom policies | Application layer protection | Web app security |
| **DNS Failover** | Route53 | Health checks, weighted routing | High availability | Disaster recovery |
| **SSL/TLS** | Certificates | Certificate management | Data encryption | Secure communications |
| **Network Segmentation** | Subnets/VLANs | Micro-segmentation | Limit blast radius | Zero trust architecture |

### **Network Architecture Diagram**
```
Internet
    │
    ▼
┌───────────────────┐
│   F5 BIG-IP       │  ◄─── Layer 4/7 Load Balancing
│   (External LB)   │       SSL Termination
└─────────┬─────────┘       DDoS Protection
          │
          ▼
┌───────────────────┐
│   Imperva WAF     │  ◄─── Web Application Firewall
│   (Security)      │       OWASP Protection
└─────────┬─────────┘       Bot Mitigation
          │
          ▼
┌───────────────────┐
│     AWS ALB       │  ◄─── Path-based Routing
│   (Internal LB)   │       Health Checks
└─────────┬─────────┘       Target Groups
          │
     ┌────┴────┐
     ▼         ▼
┌─────────┐ ┌─────────┐
│ Web App │ │ API App │  ◄─── Auto Scaling Groups
│ Servers │ │ Servers │       Security Groups
└─────────┘ └─────────┘       Private Subnets
```

---

## 📋 QUICK REFERENCE CARDS

### **🐍 Python Time Complexity**
| **Data Structure** | **Access** | **Search** | **Insert** | **Delete** | **Memory** |
|-------------------|-----------|-----------|-----------|-----------|------------|
| **List** | O(1) | O(n) | O(n) | O(n) | O(n) |
| **Dict** | O(1) avg | O(1) avg | O(1) avg | O(1) avg | O(n) |
| **Set** | N/A | O(1) avg | O(1) avg | O(1) avg | O(n) |
| **Tuple** | O(1) | O(n) | N/A | N/A | O(n) |
| **Deque** | O(1) ends | O(n) | O(1) ends | O(1) ends | O(n) |

### **🧠 Algorithm Complexity**
| **Algorithm** | **Best** | **Average** | **Worst** | **Space** | **Stable** |
|--------------|----------|-------------|-----------|-----------|------------|
| **Quick Sort** | O(n log n) | O(n log n) | O(n²) | O(log n) | No |
| **Merge Sort** | O(n log n) | O(n log n) | O(n log n) | O(n) | Yes |
| **Binary Search** | O(1) | O(log n) | O(log n) | O(1) | N/A |
| **DFS/BFS** | O(V+E) | O(V+E) | O(V+E) | O(V) | N/A |

### **☁️ AWS Quick Commands**
```bash
# EC2
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress]'

# S3
aws s3 ls s3://bucket-name --recursive --human-readable --summarize

# RDS
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus,Endpoint.Address]'

# EKS
aws eks list-clusters
kubectl get nodes
kubectl get pods -A

# CloudWatch
aws logs describe-log-groups --query 'logGroups[*].logGroupName'
```

### **🏗️ Terraform Quick Commands**
```bash
terraform init          # Initialize working directory
terraform fmt           # Format code
terraform validate      # Validate configuration
terraform plan          # Preview changes
terraform apply         # Apply changes
terraform destroy       # Remove resources
terraform workspace list # List workspaces
terraform state list    # List resources in state
```

### **🐳 Docker Quick Commands**
```bash
docker ps -a                    # List all containers
docker images                   # List all images
docker build -t app:latest .    # Build image
docker run -d -p 80:8080 app    # Run container
docker exec -it container bash  # Execute in container
docker logs container           # View logs
docker-compose up -d            # Start services
```

### **⎈ Kubernetes Quick Commands**
```bash
kubectl get pods -o wide        # List pods with details
kubectl describe pod <name>     # Pod details
kubectl logs -f <pod>           # Follow logs
kubectl exec -it <pod> -- bash  # Execute in pod
kubectl apply -f deployment.yaml # Apply manifest
kubectl get svc                 # List services
kubectl scale deployment app --replicas=5 # Scale deployment
```

---

## 🎯 **INTERVIEW SUCCESS TIPS**

### **🔥 Most Asked Questions**
1. **"Explain the difference between RDS Multi-AZ and Read Replicas"**
2. **"How would you design a highly available web application?"**
3. **"What's the difference between Security Groups and NACLs?"**
4. **"How do you handle secrets in Kubernetes?"**
5. **"Explain Terraform state management in a team environment"**

### **💡 Interview Strategy**
- ✅ **Always mention time/space complexity** for algorithms
- ✅ **Draw diagrams** for system design questions
- ✅ **Explain trade-offs** between different approaches
- ✅ **Use real-world examples** from your experience
- ✅ **Ask clarifying questions** before solving problems

### **📊 Key Metrics to Know**
- **EC2**: Instance types, pricing models
- **RDS**: IOPS, connection limits, backup retention
- **Lambda**: Memory limits, timeout, concurrent executions
- **ALB**: Connection limits, target health checks
- **EKS**: Pod limits per node, cluster autoscaler

---

*This comprehensive cheat sheet covers the most frequently asked DevOps/SRE interview topics. Practice explaining these concepts in your own words and be ready to code algorithms on a whiteboard.* 🚀
