# Getting Started

<video controls="" autoplay="" name="media"><source src="https://github.com/blacklanternsecurity/saudit/assets/20261699/e539e89b-92ea-46fa-b893-9cde94eebf81" type="video/mp4"></video>

_A SAUDIT scan in real-time - visualization with [VivaGraphJS](https://github.com/blacklanternsecurity/saudit-vivagraphjs)_

## Installation

!!! info "Supported Platforms"

    Only **Linux** is supported at this time. **Windows** and **macOS** are *not* supported. If you use one of these platforms, consider using [Docker](#docker).

SAUDIT offers multiple methods of installation, including **pipx** and **Docker**. If you're looking to tinker or write your own module, see [Setting up a Dev Environment](./dev/dev_environment.md).

### [Python (pip / pipx)](https://pypi.org/project/saudit/)


???+ note inline end

    `pipx` installs SAUDIT inside its own virtual environment.

```bash
# stable version
pipx install saudit

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' saudit

# execute saudit command
saudit --help
```

### Docker

[Docker images](https://hub.docker.com/r/blacklanternsecurity/saudit) are provided, along with helper script `saudit-docker.sh` to persist your scan data. Images come in four flavors: `dev`, `dev-full`, `stable`, and `stable-full`. `dev` is the latest bleeding edge version. `-full` images are larger and have all of SAUDIT's module dependencies preinstalled (wordlists, pip packages, etc.).

Scans are output to `~/.saudit/scans` (the usual place for SAUDIT scan data).

```bash
# dev (bleeding edge)
docker run -it blacklanternsecurity/saudit --help
# dev (bleeding edge - full)
docker run -it blacklanternsecurity/saudit:dev-full --help

# stable
docker run -it blacklanternsecurity/saudit:stable --help
# stable (full)
docker run -it blacklanternsecurity/saudit:stable-full --help

# helper script
git clone https://github.com/blacklanternsecurity/saudit && cd saudit
./saudit-docker.sh --help
```

Note: If you need to pass in a custom preset, you can do so by mapping the preset into the container:

```bash
# use the preset `my_preset.yml` from the current directory
docker run --rm -it \
  -v "$HOME/.saudit/scans:/root/.saudit/scans" \
  -v "$PWD/my_preset.yml:/my_preset.yml" \
  blacklanternsecurity/saudit -p /my_preset.yml
```

## Example Commands

Below are some examples of common scans.

<!-- SAUDIT EXAMPLE COMMANDS -->
**Subdomains:**

```bash
# Perform a full subdomain enumeration on evilcorp.com
saudit -t evilcorp.com -p subdomain-enum
```

**Subdomains (passive only):**

```bash
# Perform a passive-only subdomain enumeration on evilcorp.com
saudit -t evilcorp.com -p subdomain-enum -rf passive
```

**Subdomains + port scan + web screenshots:**

```bash
# Port-scan every subdomain, screenshot every webpage, output to current directory
saudit -t evilcorp.com -p subdomain-enum -m portscan gowitness -n my_scan -o .
```

**Subdomains + basic web scan:**

```bash
# A basic web scan includes robots.txt, storage buckets, IIS shortnames, and other non-intrusive web modules
saudit -t evilcorp.com -p subdomain-enum web-basic
```

**Web spider:**

```bash
# Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.
saudit -t www.evilcorp.com -p spider -c web.spider_distance=2 web.spider_depth=2
```

**Everything everywhere all at once:**

```bash
# Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei
saudit -t evilcorp.com -p kitchen-sink
```
<!-- END SAUDIT EXAMPLE COMMANDS -->

## API Keys

SAUDIT works just fine without API keys. However, there are certain modules that need them to function. If you have API keys and want to make use of these modules, you can place them either in your preset:

```yaml title="my_preset.yml"
description: My custom subdomain enum preset

include:
  - subdomain-enum
  - cloud-enum

config:
  modules:
    shodan_dns:
      api_key: deadbeef
    virustotal:
      api_key: cafebabe
```

...in SAUDIT's global YAML config (`~/.config/saudit/saudit.yml`):

Note: this will ensure the API keys are used in all scans, regardless of preset.

```yaml title="~/.config/saudit/saudit.yml"
modules:
  shodan_dns:
    api_key: deadbeef
  virustotal:
    api_key: cafebabe
```

...or directly on the command-line:

```bash
# specify API key with -c
saudit -t evilcorp.com -f subdomain-enum -c modules.shodan_dns.api_key=deadbeef modules.virustotal.api_key=cafebabe
```

For more information, see [Configuration](./scanning/configuration.md). For a full list of modules, including which ones require API keys, see [List of Modules](./modules/list_of_modules.md).

[Next Up: Scanning -->](./scanning/index.md){ .md-button .md-button--primary }
