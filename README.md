<p align="center">
<img src="https://github.com/martinkubecka/C2Hunter/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Utilize fingerprinting techniques to actively hunt for Command and Control (C2) servers on Shodan.</b><br> In addition, incorporate threat feeds from Feodo Tracker, ThreatFox, and URLhaus to generate a personalized, local database of C2 servers.</p>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [:notebook_with_decorative_cover: Pre-requisites](#notebook_with_decorative_cover-pre-requisites)
    - [:package: Installing Required Packages](#package-installing-required-packages)
    - [:old_key: API Key](#old_key-api-key)
- [:eagle: Usage](#eagle-usage)
- [:open_file_folder: Resources](#open_file_folder-resources)
- [:toolbox: Development](#toolbox-development)
    - [:office: Virtual environment](#office-virtual-environment)

---

## :notebook_with_decorative_cover: Pre-requisites

- the current version requires **Linux** based operating system
- install [Python](https://www.python.org/downloads/) version >= 3.6
- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/C2Hunter.git
```

- in the `config` directory create `config.yml` file based on the `config/example.yml` structure 

### :package: Installing Required Packages

```
$ pip install -r requirements.txt
```

### :old_key: API Key

- add your [Shodan](https://developer.shodan.io/) API key to the newly created `config/config.yml` file

> ***Note:*** *Shodan's Freelancer Plan may not be sufficient based on the frequency with which this application is
run.*

---

## :eagle: Usage

```
usage: c2hunter.py [-h] [-q] [-c FILE] [-o DIRECTORY] [-s] [-p] [-ds] [-df] [-du] [-dt] [-db]

Utilize fingerprinting techniques to actively hunt for Command and Control (C2) servers on Shodan. 
In addition, incorporate threat feeds from Feodo Tracker, ThreatFox, and URLhaus to generate a personalized, local database of C2 servers.

options:
  -h, --help                        show this help message and exit
  -q, --quiet                       do not print a banner
  -c FILE, --config FILE            config file (default: "config/config.yml")
  -o DIRECTORY, --output DIRECTORY  output directory (default: "reports/")
  -s, --search-country-code         search IoCs based on the configured country code
  -p, --print-active                print filtered active endpoints to the console

disable options:
  -ds, --disable-shodan             disable querying Shodan
  -df, --disable-feodotracker       disable querying Feodo Tracker
  -du, --disable-urlhaus            disable querying URLhaus
  -dt, --disable-threatfox          disable querying ThreatFox
  -db, --disable-backup             disable file reports backup
```

---
## :open_file_folder: Resources

- [Detecting and Fingerprinting Infostealer Malware-as-a-Service platforms](https://blog.bushidotoken.net/2022/11/detecting-and-fingerprinting.html) by [@BushidoToken](https://twitter.com/BushidoToken)
  - [Shodan search operators](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md)
- [Hunting Cobalt Strike C2 with Shodan](https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2) by [@MichalKoczwara](https://twitter.com/MichalKoczwara)
- [Hunting C2](https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f) by [@MichalKoczwara](https://twitter.com/MichalKoczwara)

---
## :toolbox: Development

### :office: Virtual environment

1. use your package manager to install `python-pip` if it is not present on your system
2. install `virtualenv`
3. verify installation by checking the `virtualenv` version
4. inside the project directory create a virtual environment called `venv`
5. activate it by using the `source` command
6. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

```
$ sudo apt-get install python-pip
$ pip install virtualenv
$ virtualenv --version
$ virtualenv --python=python3 venv
$ source venv/bin/activate
$ deactivate
```

---

<div align="right">
<a href="#table-of-contents">[ Table of Contents ]</a>
</div>