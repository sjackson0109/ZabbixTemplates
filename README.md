## Overview
This repository contains custom scripts designed for **Zabbix Monitoring**. Each script is documented individually, providing installation instructions, usage examples, and integration details.

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Scripts:
- **[WatchGuard System Health Check](readme-watchguard.md)** - Logs into a WatchGuard Firewall, retrieves system health metrics, and calculates a health score for Zabbix. Returns a integer from 1 to 100 (healthy).
- **[get_sip_options.py](README-SIP-Options.md)** - A Python script designed to send SIP OPTIONS requests to a specified SIP server and verify its response. The script is fully compliant with RFC 3261 and supports a wide variety of optional arguments.
- **[get_firebox_health.py](README-WatchguardSystemHealth.md)** - This script logs into a **WatchGuard Firewall**, retrieves **system health metrics**, and calculates a **health score** for monitoring in **Zabbix** (still under development)

- **[Script C](readme-C.md)** - Description of Script C.

## Prerequsites
Your zabbix-proxy docker containers will need pyhon installed, to be able to use any of these plugins.

1. Download the build `Dockerfile` in this repo [here](./dockerfile/zabbix_proxy_mysql_alpine_python3), save this adjacent to your docker-compose.yaml file.

2. Update your docker-compose.yml file.
From:
```yaml
services:

  zabbix-proxy:
    image: zabbix/zabbix-proxy-mysql:alpine-7.0-latest
    container_name: zabbix-proxy
    restart: unless-stopped
    env_file:
      .env
```

To:
```yaml
services:

  zabbix-proxy:
    #image: zabbix/zabbix-proxy-mysql:alpine-7.0-latest
    build:
      context: .
      dockerfile: zabbix_proxy_mysql_alpine_python3
    container_name: zabbix-proxy
    restart: unless-stopped
    env_file:
      .env
```
    
2. Rebuild your containers:
```bash
docker compose down && docker compose up -d --force-recreate --build
```
Output looks like this:
```bash
[+] Running 3/3
 ✔ Container zabbix-proxy       Removed                                                            2.5s 
 ✔ Container zabbix-mysql       Removed                                                            2.2s 
 ✔ Network prod_zabbix-network  Removed                                                            0.3s 
[+] Building 8.1s (10/10) FINISHED                                                       docker:default
 => [zabbix-proxy internal] load build definition from dockerfile                                  0.0s
 => => transferring dockerfile: 476B                                                               0.0s
 => [zabbix-proxy internal] load metadata for docker.io/zabbix/zabbix-proxy-mysql:alpine-7.0-late  0.0s
 => [zabbix-proxy internal] load .dockerignore                                                     0.0s
 => => transferring context: 2B                                                                    0.0s
 => CACHED [zabbix-proxy 1/5] FROM docker.io/zabbix/zabbix-proxy-mysql:alpine-7.0-latest           0.0s
 => [zabbix-proxy 2/5] RUN apk add --no-cache python3 py3-pip                                      2.5s
 => [zabbix-proxy 3/5] RUN pip3 install requests --break-system-packages                           2.8s 
 => [zabbix-proxy 4/5] RUN pip3 install py-zabbix --break-system-packages                          1.1s 
 => [zabbix-proxy 5/5] RUN python3 --version && pip3 --version && python3 -m pip show requests     1.0s 
 => [zabbix-proxy] exporting to image                                                              0.5s 
 => => exporting layers                                                                            0.5s 
 => => writing image sha256:fbdf1a3a0bb4b166e60f9d56f7f12237a677eb0ac2a0eaef72bb4c9548d772a1       0.0s 
 => => naming to docker.io/library/prod-zabbix-proxy                                               0.0s 
 => [zabbix-proxy] resolving provenance for metadata file                                          0.0s
[+] Running 4/4
 ✔ zabbix-proxy                 Built                                                              0.0s 
 ✔ Network prod_zabbix-network  Created                                                            0.1s 
 ✔ Container zabbix-mysql       Started                                                            0.4s 
 ✔ Container zabbix-proxy       Started                                                            0.6s 
```

## Installation
For usage details of each script, refer to the individual README files linked above; generic installation, means cloning the .py script into the externalscripts folder on your proxy. Then importing the template XML file into the Zabbix Condole > Data Collection > Templates > Import.

## Notes
- Scripts are designed to integrate with **Zabbix Proxy** and **Zabbix Server**.
- Each script follows best practices for **error handling**, **logging**, and **parameterisation**.
- Contributions and improvements are welcome.

## License
This project is licensed under the **Apache License 2.0**.  
See the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) for details.