<p align="center">
<img src="https://github.com/martinkubecka/C2Hunter/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b></b><br>
</p>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [:notebook_with_decorative_cover: Pre-requisites](#notebook_with_decorative_cover-pre-requisites)
  - [:package: Installing Required Packages](#package-installing-required-packages)
  - [:old_key: API Key](#old_key-api-key)
- [:eagle: Usage](#eagle-usage)
- [:toolbox: Development](#toolbox-development)
  - [:office: Virtual environment](#office-virtual-environment)

---
## :notebook_with_decorative_cover: Pre-requisites

- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/C2Hunter.git
```

- create `config.yml` based on the `example.yml` file inside `config` directory

### :package: Installing Required Packages

```
$ pip install -r requirements.txt
```

### :old_key: API Key

- create `config/config.yml` file structured as `config/example.yml`
- add your Shodan API key to the `config/config.yml` file 

> ***Note:*** *Shodan's Freelancer Plan may not be sufficient based on the frequency with which this application is run.*

---
## :eagle: Usage

```
usage: c2hunter.py [-h] [-q] [-c FILE] [-o DIRECTORY] [-p] [-ds] [-df] [-du] [-dt] [-db]

DESCRIPTION

options:
  -h, --help                        show this help message and exit
  -q, --quiet                       do not print a banner
  -c FILE, --config FILE            config file (default: "config/config.yml")
  -o DIRECTORY, --output DIRECTORY  output directory (default: "reports/")
  -p, --print-active                print filtered active enpoints to the console

disable options:
  -ds, --disable-shodan             disable querying Shodan
  -df, --disable-feodotracker       disable querying Feodo Tracker
  -du, --disable-urlhaus            disable querying URLhaus
  -dt, --disable-threatfox          disable querying ThreatFox
  -db, --disable-backup             disable file reports backup
```

---
## :toolbox: Development

### :office: Virtual environment

1. use your package manager to install `python-pip` if it is not present on your system
3. install `virtualenv`
4. verify installation by checking the `virtualenv` version
5. inside the project directory create a virtual environment called `venv`
6. activate it by using the `source` command
7. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

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