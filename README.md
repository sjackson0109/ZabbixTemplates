## Overview
This repository contains custom scripts designed for **Zabbix Monitoring**. Each script is documented individually, providing installation instructions, usage examples, and integration details.

## Structure
All custom monitoring scripts reside under this repository. Below are the available scripts with their respective documentation:

### Available Templates

- **[Zabbix Template: Sonicwall Firewall](README-Template_Sonicwall_Firewall.md)** - A complete MIB pack evaluation of what is possible to walk (discovery rules) and what can be created manually (items). Spent approx 2 weeks testing, and customising graphs, triggers and the device dashboard.
- **[Zabbix Template: Watchguard Firebox](README-Template_Watchguard_Firebox.md)** - A very large expansion on the community module of the original `Watchguard Firebox M400`. I now have approx 500 metrics on a HA pair in our datacentre. Items, item-triggers, graphs and even dashboards are all discovered now.
- **[Zabbix Template: Ubiquiti Firewall](README-Template_Ubiquiti_Firewall.md)** - Another complete seveeral MIB packs; tested on a UCG and USG, no other devices available to test against. Spent approx 1 weeks testing, and customising graphs, triggers and the device dashboard.

### Available Scripts:
- **[get_tcp_port_scan.py](README-TCP-Port-Scan.md)** - A multithreaded TCP scanner written in Python3, built to assist with service discovery and exposure audits. It’s designed for use with Zabbix low-level discovery (LLD), but can also be used interactively from the command line. 
- **[get_sip_options.py](README-SIP-Options.md)** - A Python script designed to send SIP OPTIONS requests to a specified SIP server and verify its response. The script is fully compliant with RFC 3261 and supports a wide variety of optional arguments.
- **[get_tls_handshake.py](README-TLS-Handshake.md)** - A Python script designed to test TLS handshake capabilities of a specified HOST (Hostname, FQDN or IP endpoint). It dynamically detects the available SSL/TLS protocols and ciphers on the client-system, tests their compatibility against the supplied host/port, and provides a breakdown report of successful and failed connections.


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