# ThreatWorx Bitbucket App

## _Zero Trust Automated AppSec for Bitbucket Cloud_

A complete automated AppSec solution part of the ThreatWorx proactive security platform which discovers your Bitbucket Cloud repositories and finds vulnerable dependencies, run static tests on code and Infrastructure-As-Code files, finds embedded secrets and more.

## Features

- Code doesn't leave your premises even for scanning - zero trust scan
- Packaged as a container for easy on-premise deployment
- Support for open source vulns and IaC scanning
- Support for on-premise / hosted GitLab Enterprise service
- Auto upgrade using watchtower

## Requirements

- Standard linux system (Redhat, Ubuntu, CentOS etc.) with docker support and port 443 (https) inbound / outbound connectivity and atleast 100GB storage
- SSL certificate for secure communication with Bitbucket Cloud (optional). App supports and will allow creating self signed certificates if none are available.
- Bitbucket App requires 'read' permissions for repository content

## Setup Bitbucket {Workspace,Project,Repository} access token

- The app uses Bitbucket access tokens to clone repositories for scanning. If you have multiple projects or repositories, then please create access token at Workspace level.

- Please specify 'Scope' as 'Repositories -> Read' for the access token

- Remember to copy / store the access token for use later when configuring the app server

## Install and configure the App Service

- Ensure requirements are satisfied on linux system, especially docker support and https inbound / outbound connectivity

- Download / clone the [ThreatWorx Bitbucket App](https://github.com/threatworx/bitbucket_app) repository

```bash
git clone https://github.com/threatworx/bitbucket_app.git
```

- Run the setup.sh script to create self signed certificates

```bash
cd bitbucket_app
./setup.sh
```

> If you have ssl certificates, copy them to the ``config`` directory and edit the ``uwsgi.ini`` to use your certificates

```
[uwsgi]
...
https = =0,/opt/tw_bitbucket_app/config/my.cert,/opt/tw_bitbucket_app/config/my.key,...
...
```

- Start the app service by running the ``docker compose`` or the ``docker-compose`` command

```bash
docker compose up -d
```

- Point a browser to ``https://linux-system`` to configure the app service

> The browser will complain about the self signed certificate if are using one
>
> Please be sure to replace it with an appropriate ssl certificate

- Provide required details of your ThreatWorx subscription on the form 

- Provide Bitbucket access token

- Select required options for app service and click ``Configure``

> These options can be changed later by editing the ``./config/config.ini`` file

> App will initially do a complete dependency vulnerability scan for all selected repositories
>
> After that, any push will trigger a rescan of the change that is committed

## Setup Bitbucket Cloud webhook

- The app uses Bitbucket Cloud webhook to receive events such as a repostory push

- To setup a webhook go to your `Repository->Repository settings->Webhooks`

- Set an appropriate 'Title'

- Set the URL for the webhook to `https://<your app server>/webhook`


- Select `Push` event under `Repository` as the trigger

- If you are using self signed SSL certificates, you can check `Skip certificate verification`

- Secure your webhook by ensuring that only Bitbucket IPs can comminucate with it [(learn more)](https://support.atlassian.com/bitbucket-cloud/docs/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall/)

