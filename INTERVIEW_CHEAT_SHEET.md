# 🎯 ULTIMATE INTERVIEW CHEAT SHEET
## Python + DSA + AWS + DevOps + Networking + Terraform

---

## 📚 TABLE OF CONTENTS
1. [Python Data Structures](#python-data-structures)
2. [DSA Algorithms](#dsa-algorithms) 
3. [AWS Services](#aws-services)
4. [Networking & Security](#networking--security)
5. [DevOps Tools](#devops-tools)
6. [System Design Patterns](#system-design-patterns)
7. [Interview Q&A](#interview-qa)

---

## 🐍 PYTHON DATA STRUCTURES

### **Lists** - Dynamic Arrays
```python
# Creation and Basic Operations
servers = ["web-01", "api-01", "db-01"]
servers.append("cache-01")      # O(1) - Add to end
servers.insert(0, "lb-01")      # O(n) - Insert at position
servers.remove("api-01")        # O(n) - Remove by value  
servers.pop(0)                  # O(n) - Remove by index
```

| Operation | Time Complexity | Use Case |
|-----------|----------------|----------|
| Access | O(1) | Get server by index |
| Append | O(1) amortized | Add new server |
| Insert | O(n) | Insert at specific position |
| Delete | O(n) | Remove server from list |
| Search | O(n) | Find server in list |

### **Dictionaries** - Hash Maps
```python
# Server metadata
server_config = {
    "hostname": "web-prod-01",
    "region": "us-west-2",
    "instance_type": "t3.medium",
    "status": "running"
}

# Operations
server_config["cpu_usage"] = 45.2    # O(1) - Set value
cpu = server_config.get("cpu_usage", 0)  # O(1) - Get with default
server_config.pop("temp", None)      # O(1) - Safe removal
```

| Operation | Time Complexity | Use Case |
|-----------|----------------|----------|
| Get | O(1) avg, O(n) worst | Configuration lookup |
| Set | O(1) avg, O(n) worst | Update server metadata |
| Delete | O(1) avg, O(n) worst | Remove config key |
| Contains | O(1) avg, O(n) worst | Check if key exists |

### **Sets** - Unique Collections
```python
# IP address management
allowed_ips = {"10.0.1.1", "10.0.1.2", "10.0.2.1"}
blocked_ips = {"192.168.1.100", "10.0.1.1"}

# Set operations
all_ips = allowed_ips | blocked_ips      # Union
conflicted = allowed_ips & blocked_ips   # Intersection  
clean_allowed = allowed_ips - blocked_ips # Difference
```

### **Tuples** - Immutable Sequences
```python
# Database connection config (shouldn't change during runtime)
db_config = ("localhost", 5432, "postgres", "production")
host, port, database, environment = db_config  # Tuple unpacking
```

---

## 🧠 DSA ALGORITHMS

### **Binary Search** - O(log n)
```python
def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    
    while left <= right:
        mid = (left + right) // 2
        
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    
    return -1

# Example: Find server in sorted list
servers = ["api-01", "db-01", "web-01", "web-02"]
index = binary_search(servers, "db-01")  # Returns 1
```

**When to use:** Searching in sorted data, server IPs, configuration values

### **Quick Sort** - O(n log n) average
```python
def quick_sort(arr):
    if len(arr) <= 1:
        return arr
    
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    
    return quick_sort(left) + middle + quick_sort(right)

# Example: Sort server metrics by CPU usage
metrics = [(85, "web-01"), (23, "web-02"), (91, "db-01")]
sorted_metrics = quick_sort(metrics)
```

### **Graph Traversal** - O(V + E)

#### **DFS (Depth-First Search)**
```python
def dfs(graph, start, visited=None):
    if visited is None:
        visited = set()
    
    visited.add(start)
    result = [start]
    
    for neighbor in graph.get(start, []):
        if neighbor not in visited:
            result.extend(dfs(graph, neighbor, visited))
    
    return result

# Infrastructure dependency graph
infrastructure = {
    "load-balancer": ["web-01", "web-02"],
    "web-01": ["api-01"],
    "web-02": ["api-01"], 
    "api-01": ["db-01"],
    "db-01": []
}

# Find all dependent services
dependencies = dfs(infrastructure, "load-balancer")
```

#### **BFS (Breadth-First Search)**
```python
from collections import deque

def bfs(graph, start):
    visited = {start}
    queue = deque([start])
    result = []
    
    while queue:
        node = queue.popleft()
        result.append(node)
        
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    
    return result
```

### **Hash Table Patterns**

#### **Two Sum** - Interview Favorite
```python
def two_sum(nums, target):
    num_map = {}
    
    for i, num in enumerate(nums):
        complement = target - num
        if complement in num_map:
            return [num_map[complement], i]
        num_map[num] = i
    
    return []

# Example: Find two servers that sum to target capacity
capacities = [2, 7, 11, 15]
target_capacity = 9
indices = two_sum(capacities, target_capacity)  # Returns [0, 1]
```

---

## ☁️ AWS SERVICES

### **RDS (Relational Database Service)**

#### **Key Concepts:**
- **Multi-AZ**: High availability with automatic failover
- **Read Replicas**: Scale read operations across regions
- **Automated Backups**: Point-in-time recovery up to 35 days
- **Parameter Groups**: Database configuration management

#### **Common Interview Questions:**
```python
# Creating RDS instance with Boto3
import boto3

rds = boto3.client('rds')

# Create MySQL instance
response = rds.create_db_instance(
    DBInstanceIdentifier='prod-mysql',
    DBInstanceClass='db.t3.micro',
    Engine='mysql',
    EngineVersion='8.0.35',
    MasterUsername='admin',
    MasterUserPassword='SecurePass123!',
    AllocatedStorage=20,
    VpcSecurityGroupIds=['sg-12345'],
    MultiAZ=True,                    # High availability
    BackupRetentionPeriod=7,         # 7 days backup retention
    StorageEncrypted=True            # Encryption at rest
)
```

#### **Scaling Strategies:**
1. **Vertical Scaling**: Increase instance size
2. **Read Replicas**: Create read-only copies
3. **Connection Pooling**: Use RDS Proxy
4. **Sharding**: Distribute data across multiple databases

### **DynamoDB (NoSQL Database)**

#### **Key Concepts:**
- **Partition Key**: Primary key for data distribution
- **Sort Key**: Optional secondary key for sorting
- **GSI/LSI**: Global/Local Secondary Indexes
- **DynamoDB Streams**: Change data capture

```python
# DynamoDB operations
dynamodb = boto3.resource('dynamodb')

# Create table
table = dynamodb.create_table(
    TableName='UserSessions',
    KeySchema=[
        {'AttributeName': 'userId', 'KeyType': 'HASH'},      # Partition key
        {'AttributeName': 'sessionId', 'KeyType': 'RANGE'}   # Sort key
    ],
    AttributeDefinitions=[
        {'AttributeName': 'userId', 'AttributeType': 'S'},
        {'AttributeName': 'sessionId', 'AttributeType': 'S'},
        {'AttributeName': 'timestamp', 'AttributeType': 'N'}
    ],
    BillingMode='PAY_PER_REQUEST',
    GlobalSecondaryIndexes=[{
        'IndexName': 'timestamp-index',
        'KeySchema': [{'AttributeName': 'timestamp', 'KeyType': 'HASH'}],
        'Projection': {'ProjectionType': 'ALL'}
    }]
)

# CRUD operations
table = dynamodb.Table('UserSessions')

# Create
table.put_item(Item={
    'userId': 'user123',
    'sessionId': 'session456', 
    'timestamp': 1642234567,
    'data': {'login_time': '2024-01-15T10:00:00Z'}
})

# Read
response = table.get_item(
    Key={'userId': 'user123', 'sessionId': 'session456'}
)

# Query with GSI
response = table.query(
    IndexName='timestamp-index',
    KeyConditionExpression='timestamp = :ts',
    ExpressionAttributeValues={':ts': 1642234567}
)
```

### **ElastiCache (Redis)**

#### **Redis Data Types & Use Cases:**
```bash
# String operations - Session storage
SET user:1000 "John Doe"
GET user:1000
EXPIRE user:1000 3600

# Hash operations - User profiles  
HSET user:1001 name "Jane Doe" email "jane@example.com" age 25
HGETALL user:1001

# List operations - Task queues
LPUSH queue:tasks "deploy-app" "backup-db" "update-dns"
RPOP queue:tasks

# Set operations - Tags, categories
SADD user:tags "developer" "python" "aws"
SMEMBERS user:tags

# Sorted Set operations - Leaderboards
ZADD leaderboard 1500 "player1" 1200 "player2" 1800 "player3"
ZRANGE leaderboard 0 -1 WITHSCORES
```

#### **Redis Clustering:**
- **Master-Slave**: Read scaling with failover
- **Redis Cluster**: Horizontal partitioning
- **Redis Sentinel**: High availability monitoring

### **MSK (Managed Streaming for Kafka)**

#### **Kafka Concepts:**
- **Topic**: Stream of records
- **Partition**: Ordered sequence within topic  
- **Producer**: Publishes records to topics
- **Consumer**: Reads records from topics
- **Consumer Group**: Load balancing consumers

```python
# Create MSK cluster
msk = boto3.client('kafka')

response = msk.create_cluster(
    BrokerNodeGroupInfo={
        'BrokerAZDistribution': 'DEFAULT',
        'InstanceType': 'kafka.t3.small',
        'ClientSubnets': ['subnet-12345', 'subnet-67890'],
        'SecurityGroups': ['sg-kafka']
    },
    ClusterName='prod-kafka',
    KafkaVersion='2.8.1',
    NumberOfBrokerNodes=3,
    EncryptionInfo={
        'EncryptionInTransit': {
            'ClientBroker': 'TLS',
            'InCluster': True
        }
    }
)
```

### **EKS (Elastic Kubernetes Service)**

#### **Key Components:**
- **Control Plane**: Managed by AWS
- **Worker Nodes**: EC2 instances running pods
- **Node Groups**: Managed scaling groups
- **Fargate**: Serverless containers

```python
# Create EKS cluster
eks = boto3.client('eks')

cluster = eks.create_cluster(
    name='prod-eks',
    version='1.28',
    roleArn='arn:aws:iam::123456789012:role/eksServiceRole',
    resourcesVpcConfig={
        'subnetIds': ['subnet-12345', 'subnet-67890'],
        'securityGroupIds': ['sg-eks'],
        'endpointConfigPrivate': True,
        'endpointConfigPublic': True
    },
    logging={
        'clusterLogging': [{
            'types': ['api', 'audit', 'authenticator'],
            'enabled': True
        }]
    }
)

# Create node group
nodegroup = eks.create_nodegroup(
    clusterName='prod-eks',
    nodegroupName='worker-nodes',
    scalingConfig={
        'minSize': 1,
        'maxSize': 10,
        'desiredSize': 3
    },
    instanceTypes=['t3.medium'],
    subnets=['subnet-12345', 'subnet-67890'],
    nodeRole='arn:aws:iam::123456789012:role/NodeInstanceRole'
)
```

---

## 🌐 NETWORKING & SECURITY

### **VPC (Virtual Private Cloud)**

#### **VPC Architecture Diagram:**
```
Internet Gateway
       |
   Public Subnet (10.0.1.0/24)
   [Web Servers + Load Balancer]
       |
   Private Subnet (10.0.2.0/24)  
   [Application Servers]
       |
   Private Subnet (10.0.3.0/24)
   [Database Servers]
       |
   NAT Gateway (for outbound)
```

#### **VPC Components:**
- **CIDR Block**: IP address range (e.g., 10.0.0.0/16)
- **Subnets**: Subdivisions within VPC
- **Route Tables**: Network traffic routing rules
- **Internet Gateway**: Internet access for public subnets
- **NAT Gateway**: Outbound internet access for private subnets

```python
# Create VPC infrastructure
ec2 = boto3.client('ec2')

# Create VPC
vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
vpc_id = vpc['Vpc']['VpcId']

# Create Internet Gateway
igw = ec2.create_internet_gateway()
ec2.attach_internet_gateway(
    InternetGatewayId=igw['InternetGateway']['InternetGatewayId'],
    VpcId=vpc_id
)

# Create Public Subnet
public_subnet = ec2.create_subnet(
    VpcId=vpc_id,
    CidrBlock='10.0.1.0/24',
    AvailabilityZone='us-west-2a'
)

# Create Private Subnet  
private_subnet = ec2.create_subnet(
    VpcId=vpc_id,
    CidrBlock='10.0.2.0/24',
    AvailabilityZone='us-west-2a'
)
```

### **Security Groups vs NACLs**

| Feature | Security Groups | Network ACLs |
|---------|----------------|--------------|
| **Level** | Instance level | Subnet level |
| **Rules** | Allow rules only | Allow & Deny rules |
| **State** | Stateful | Stateless |
| **Evaluation** | All rules evaluated | Rules processed in order |
| **Default** | Deny all inbound, Allow all outbound | Allow all traffic |

### **Load Balancer Types**

#### **Application Load Balancer (ALB)** - Layer 7
```
┌─────────────────┐
│   Users/Apps    │
└─────────┬───────┘
          │
┌─────────▼───────┐
│  ALB (Layer 7)  │  ◄── HTTP/HTTPS routing
│  Path-based     │      Host-based routing
│  SSL termination│      WebSocket support
└─────────┬───────┘
          │
┌─────────▼───────┐
│  Target Groups  │
│  ├─ Web-01      │
│  ├─ Web-02      │  
│  └─ Web-03      │
└─────────────────┘
```

#### **Network Load Balancer (NLB)** - Layer 4
- **Ultra-high performance**: Millions of requests per second
- **Static IP addresses**: Fixed IPs for whitelisting
- **Source IP preservation**: Original client IP maintained
- **Protocols**: TCP, UDP, TLS

#### **Classic Load Balancer (CLB)** - Legacy
- **Layer 4 & 7**: Basic HTTP, HTTPS, TCP support
- **Use case**: Legacy applications on EC2-Classic

### **F5 Load Balancer Concepts**

#### **F5 Components:**
```
Virtual Server (VIP:Port)
        │
    Pool (Backend servers)
        │
   Pool Members (Individual servers)
        │
   Health Monitors (Health checks)
```

- **Virtual Server**: Frontend configuration (VIP + Port + Profile)
- **Pool**: Group of backend servers
- **iRules**: Custom logic using TCL scripting
- **Profiles**: Protocol-specific settings (HTTP, SSL, TCP)
- **Persistence**: Session stickiness (cookie, source IP)
- **SNAT**: Source Network Address Translation

### **Imperva WAF (Web Application Firewall)**

#### **Security Features:**
- **Signatures**: Pre-built attack pattern detection
- **Custom Rules**: User-defined security policies
- **Bot Protection**: Automated threat detection
- **Rate Limiting**: Request throttling per IP/session
- **Data Masking**: Sensitive data protection in responses
- **Geo-blocking**: Location-based access control

#### **Policy Structure:**
```
Site Policy
├── Security Rules
│   ├── SQL Injection Prevention
│   ├── XSS Protection  
│   ├── Command Injection
│   └── Custom Rules
├── Exceptions (Whitelist)
├── Rate Limiting Rules
└── Bot Protection Settings
```

---

## 🚀 DEVOPS TOOLS

### **Terraform** - Infrastructure as Code

#### **Core Concepts:**
- **Provider**: Cloud platform (AWS, Azure, GCP)
- **Resource**: Infrastructure component
- **Data Source**: Read-only reference to existing resources
- **Variable**: Input parameter
- **Output**: Return value
- **Module**: Reusable code package

#### **Terraform Workflow:**
```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ terraform    │───▶│ terraform    │───▶│ terraform    │
│ init         │    │ plan         │    │ apply        │
│              │    │              │    │              │
│ Download     │    │ Preview      │    │ Execute      │
│ providers    │    │ changes      │    │ changes      │
└──────────────┘    └──────────────┘    └──────────────┘
```

#### **Sample Terraform Code:**
```hcl
# Provider configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-west-2"
    dynamodb_table = "terraform-lock"
  }
}

# VPC Resource
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
  }
}

# EC2 Instance with Auto Scaling
resource "aws_launch_template" "web" {
  name_prefix   = "${var.project_name}-web-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.web.id]
  
  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    environment = var.environment
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-web"
      Type = "WebServer"
    }
  }
}

# RDS Database
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-db"
  
  allocated_storage     = var.db_allocated_storage
  storage_type         = "gp3"
  storage_encrypted    = true
  
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = var.db_instance_class
  
  db_name  = var.db_name
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = var.environment == "prod" ? 30 : 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = var.environment == "dev"
  
  tags = {
    Name = "${var.project_name}-database"
  }
}
```

#### **Terraform Best Practices:**
1. **Remote State**: Use S3 backend with DynamoDB locking
2. **Modules**: Create reusable components
3. **Variables**: Use validation and descriptions
4. **Workspaces**: Separate environments
5. **Version Pinning**: Lock provider versions
6. **State Management**: Never commit .tfstate files

### **Helm** - Kubernetes Package Manager

#### **Helm Concepts:**
- **Chart**: Kubernetes application package
- **Release**: Installed chart instance
- **Repository**: Collection of charts
- **Values**: Configuration parameters
- **Templates**: Kubernetes manifest templates

#### **Helm Commands:**
```bash
# Chart management
helm create mychart              # Create new chart
helm package ./mychart           # Package chart
helm install myapp ./mychart     # Install chart
helm upgrade myapp ./mychart     # Upgrade release
helm uninstall myapp            # Remove release

# Repository management  
helm repo add stable https://charts.helm.sh/stable
helm repo update
helm search repo nginx

# Release management
helm list                       # List all releases
helm status myapp              # Check release status
helm rollback myapp 1          # Rollback to previous version
helm history myapp             # View release history
```

#### **Chart Structure:**
```
mychart/
├── Chart.yaml          # Chart metadata
├── values.yaml         # Default configuration values
├── charts/             # Chart dependencies
├── templates/          # Kubernetes manifest templates
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   └── _helpers.tpl
└── .helmignore        # Files to ignore
```

#### **Sample Helm Template:**
```yaml
# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "mychart.fullname" . }}
  labels:
    {{- include "mychart.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "mychart.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "mychart.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          ports:
            - name: http
              containerPort: {{ .Values.service.port }}
          env:
            {{- range $key, $value := .Values.env }}
            - name: {{ $key }}
              value: {{ $value | quote }}
            {{- end }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
```

### **GitLab CI/CD** - Continuous Integration & Deployment

#### **GitLab CI Concepts:**
- **Pipeline**: Automated workflow
- **Stage**: Sequential execution phase
- **Job**: Individual task within stage
- **Runner**: Agent that executes jobs
- **Artifact**: Files passed between jobs

#### **Sample .gitlab-ci.yml:**
```yaml
# Complete CI/CD pipeline
stages:
  - validate
  - build
  - test
  - security
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  KUBECONFIG: /tmp/.kube/config

# Infrastructure validation
validate_terraform:
  stage: validate
  image: hashicorp/terraform:latest
  script:
    - cd infrastructure/
    - terraform init
    - terraform fmt -check
    - terraform validate
    - terraform plan -out=tfplan
  artifacts:
    paths:
      - infrastructure/tfplan
    expire_in: 1 hour

# Application build
build_app:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE
  only:
    - main
    - develop

# Unit tests
test_unit:
  stage: test
  image: python:3.9
  script:
    - pip install -r requirements-test.txt
    - pytest tests/unit/ --cov=app --cov-report=xml
    - flake8 app/
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml

# Security scanning
security_scan:
  stage: security
  image: owasp/zap2docker-stable:latest
  script:
    - zap-baseline.py -t $APPLICATION_URL -r zap-report.html
  artifacts:
    reports:
      sast: zap-report.html
  allow_failure: true

# Deploy to staging
deploy_staging:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - echo $KUBE_CONFIG | base64 -d > $KUBECONFIG
    - helm upgrade --install myapp ./helm-chart 
        --set image.tag=$CI_COMMIT_SHA 
        --set environment=staging
        --namespace staging
  environment:
    name: staging
    url: https://staging.myapp.com
  only:
    - develop

# Deploy to production
deploy_production:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - echo $KUBE_CONFIG | base64 -d > $KUBECONFIG
    - helm upgrade --install myapp ./helm-chart 
        --set image.tag=$CI_COMMIT_SHA 
        --set environment=production
        --namespace production
  environment:
    name: production
    url: https://myapp.com
  when: manual
  only:
    - main
```

---

## 📈 SYSTEM DESIGN PATTERNS

### **Microservices Architecture**

#### **Architecture Diagram:**
```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │   (ALB/NLB)     │
                    └─────────┬───────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
        ┌───────▼───────┐ ┌───▼────┐ ┌─────▼─────┐
        │ User Service  │ │ Order  │ │  Payment  │
        │ (EKS Pod)     │ │Service │ │ Service   │
        └───────┬───────┘ └───┬────┘ └─────┬─────┘
                │             │            │
        ┌───────▼───────┐ ┌───▼────┐ ┌─────▼─────┐
        │ User Database │ │ Order  │ │  Payment  │
        │ (RDS MySQL)   │ │Database│ │ Database  │
        └───────────────┘ └────────┘ └───────────┘
```

#### **Key Patterns:**
1. **API Gateway**: Single entry point for all requests
2. **Service Discovery**: Dynamic service registration/discovery
3. **Circuit Breaker**: Prevent cascade failures
4. **Event Sourcing**: Store events instead of current state
5. **CQRS**: Separate read and write operations

### **Database Scaling Patterns**

#### **Read Scaling:**
```
Application
     │
┌────▼────┐    ┌─────────────┐
│ Master  │───▶│ Read Replica│
│Database │    │ (Read Only) │
│(R/W)    │    └─────────────┘
└─────────┘    ┌─────────────┐
               │ Read Replica│
               │ (Read Only) │
               └─────────────┘
```

#### **Horizontal Sharding:**
```
Application Layer
       │
   ┌───┴───┐
   │ Shard │
   │Router │
   └───┬───┘
       │
┌──────┼──────┐
│      │      │
▼      ▼      ▼
Shard1 Shard2 Shard3
Users  Users  Users
1-100  101-200 201-300
```

### **Caching Strategies**

#### **Cache-Aside Pattern:**
```python
def get_user(user_id):
    # Try cache first
    user = redis.get(f"user:{user_id}")
    if user:
        return json.loads(user)
    
    # Cache miss - fetch from database
    user = database.get_user(user_id)
    
    # Update cache
    redis.setex(f"user:{user_id}", 3600, json.dumps(user))
    
    return user
```

#### **Write-Through Pattern:**
```python
def update_user(user_id, data):
    # Update database
    database.update_user(user_id, data)
    
    # Update cache immediately
    redis.setex(f"user:{user_id}", 3600, json.dumps(data))
```

---

## 🎯 INTERVIEW Q&A

### **Python Questions**

**Q: What's the difference between list and tuple?**
```
A: Lists are mutable (can be changed) and use [], while tuples are 
   immutable (cannot be changed) and use (). Lists have O(n) operations 
   for insertion/deletion, tuples are more memory efficient and can be 
   used as dictionary keys.

   Use lists for: dynamic data like server inventories
   Use tuples for: fixed configuration like database credentials
```

**Q: Explain Python's Global Interpreter Lock (GIL)**
```
A: GIL allows only one thread to execute Python code at a time, making 
   CPython thread-safe but limiting true parallelism. For CPU-intensive 
   tasks, use multiprocessing. For I/O-intensive tasks (like API calls), 
   threading works well since GIL is released during I/O operations.
```

### **DSA Questions**

**Q: When would you use DFS vs BFS?**
```
A: DFS (Depth-First Search):
   - Use for: Cycle detection, topological sorting, pathfinding
   - Memory: O(h) where h is height
   - Example: Dependency resolution in package managers

   BFS (Breadth-First Search):
   - Use for: Shortest path in unweighted graphs, level-order traversal
   - Memory: O(w) where w is maximum width
   - Example: Network hop analysis, service discovery
```

**Q: How do you detect a cycle in a linked list?**
```python
def has_cycle(head):
    slow = fast = head
    
    while fast and fast.next:
        slow = slow.next
        fast = fast.next.next
        
        if slow == fast:
            return True
    
    return False

# Floyd's Cycle Detection (Tortoise and Hare)
# Time: O(n), Space: O(1)
```

### **AWS Questions**

**Q: When would you use RDS vs DynamoDB?**
```
A: RDS (Relational Database):
   - Use for: Complex queries, ACID transactions, existing SQL applications
   - Examples: Financial systems, inventory management, reporting
   
   DynamoDB (NoSQL):
   - Use for: High throughput, simple queries, gaming leaderboards
   - Examples: Session storage, IoT data, real-time analytics
```

**Q: Explain RDS Multi-AZ vs Read Replicas**
```
A: Multi-AZ:
   - Purpose: High availability and disaster recovery
   - Synchronous replication to standby in different AZ
   - Automatic failover during outages
   - Same region only

   Read Replicas:
   - Purpose: Read scaling and performance
   - Asynchronous replication
   - Can be cross-region
   - Manual promotion to master
```

### **Networking Questions**

**Q: Security Groups vs NACLs - when to use each?**
```
A: Security Groups (Instance Level):
   - Use for: Application-specific rules, dynamic environments
   - Stateful: Return traffic automatically allowed
   - Example: Allow HTTP/HTTPS to web servers

   NACLs (Subnet Level):
   - Use for: Subnet-wide protection, compliance requirements
   - Stateless: Must explicitly allow return traffic
   - Example: Block entire IP ranges, deny specific ports
```

**Q: How does ALB differ from NLB?**
```
A: Application Load Balancer (Layer 7):
   - HTTP/HTTPS routing based on path, host, headers
   - SSL termination, WebSocket support
   - Use for: Web applications, microservices

   Network Load Balancer (Layer 4):
   - TCP/UDP traffic, ultra-high performance
   - Preserves source IP, static IPs
   - Use for: Gaming, IoT, extreme performance requirements
```

### **Terraform Questions**

**Q: How do you manage Terraform state in a team environment?**
```
A: Use remote state backend with locking:

terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-west-2"
    dynamodb_table = "terraform-lock"  # Prevents concurrent runs
    encrypt        = true
  }
}

Benefits:
- Centralized state storage
- State locking prevents conflicts
- Encryption for sensitive data
- Team collaboration support
```

**Q: What are Terraform data sources vs resources?**
```
A: Resources: Create, update, delete infrastructure
   Example: aws_instance, aws_vpc

   Data Sources: Read-only access to existing infrastructure
   Example: aws_ami (find existing AMI), aws_vpc (reference existing VPC)

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
```

### **System Design Questions**

**Q: Design a URL shortener like bit.ly**
```
A: High-Level Architecture:
   1. Load Balancer (ALB)
   2. Application Servers (EKS)
   3. Cache Layer (Redis) - Hot URLs
   4. Database (DynamoDB) - URL mappings
   5. Analytics Database (RDS) - Click tracking

   URL Shortening Algorithm:
   - Base62 encoding (a-z, A-Z, 0-9) = 62^7 = 3.5 trillion URLs
   - Counter-based approach with multiple servers
   - Cache popular URLs for fast retrieval

   Scaling Considerations:
   - Read-heavy workload: Redis caching
   - Geographic distribution: CloudFront CDN
   - Analytics: Separate read replicas
   - Rate limiting: Prevent abuse
```

**Q: How would you design a chat system like Slack?**
```
A: Architecture Components:
   1. API Gateway: Authentication, rate limiting
   2. Message Service: Store/retrieve messages
   3. Notification Service: Real-time updates
   4. Presence Service: Online/offline status
   5. Media Service: File uploads/sharing

   Real-time Communication:
   - WebSocket connections for live messaging
   - Message queues (MSK/SQS) for reliable delivery
   - Push notifications for mobile users

   Data Storage:
   - Messages: DynamoDB (partition by channel)
   - User data: RDS with read replicas
   - Files: S3 with CloudFront CDN

   Scaling:
   - Horizontal scaling with load balancers
   - Database sharding by organization
   - CDN for global file distribution
```

---

## 📝 QUICK REFERENCE CARDS

### **Python Time Complexity**
| Operation | List | Dict | Set |
|-----------|------|------|-----|
| Access | O(1) | O(1) | N/A |
| Search | O(n) | O(1) | O(1) |
| Insert | O(n) | O(1) | O(1) |
| Delete | O(n) | O(1) | O(1) |

### **Sorting Algorithms**
| Algorithm | Best | Average | Worst | Space | Stable |
|-----------|------|---------|-------|-------|---------|
| Quick Sort | O(n log n) | O(n log n) | O(n²) | O(log n) | No |
| Merge Sort | O(n log n) | O(n log n) | O(n log n) | O(n) | Yes |
| Heap Sort | O(n log n) | O(n log n) | O(n log n) | O(1) | No |

### **AWS Services Quick Reference**
| Service | Type | Use Case |
|---------|------|----------|
| RDS | SQL Database | ACID transactions, complex queries |
| DynamoDB | NoSQL Database | High throughput, simple queries |
| ElastiCache | In-Memory Cache | Session storage, performance |
| MSK | Message Streaming | Event processing, real-time data |
| EKS | Container Orchestration | Microservices, scalable apps |

### **Terraform Commands**
```bash
terraform init      # Initialize working directory
terraform plan      # Preview changes
terraform apply     # Execute changes
terraform destroy   # Remove all resources
terraform fmt       # Format code
terraform validate  # Validate configuration
terraform import    # Import existing resources
```

### **Kubectl Commands**
```bash
kubectl get pods              # List pods
kubectl describe pod <name>   # Pod details
kubectl logs <pod-name>       # View logs
kubectl exec -it <pod> bash   # Shell into pod
kubectl apply -f <file>       # Apply manifest
kubectl delete -f <file>      # Delete resources
```

---

**🎯 INTERVIEW SUCCESS TIPS:**
1. **Always state time and space complexity**
2. **Explain your thought process before coding**
3. **Test with edge cases**
4. **Ask clarifying questions**
5. **Optimize if possible**
6. **Use real-world examples from your experience**

---

*This cheat sheet covers the most frequently asked interview topics for DevOps/SRE roles. Practice coding these algorithms and explaining the concepts in your own words.*