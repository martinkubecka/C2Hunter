<p align="center">
<img src="https://github.com/martinkubecka/C2Hunter/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b></b><br>
</p>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [Pre-requisites](#notebook_with_decorative_cover-pre-requisites)
  - [Installing Required Packages](#package-installing-required-packages)
- [Usage](#eagle-usage)
- [Development](#toolbox-development)
  - [Virtual environment](#office-virtual-environment)

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

---
## :eagle: Usage

```
usage: c2hunter.py [-h] [-q] [-c FILE] [--disable-shodan] [--disable-feodotracker] [--disable-urlhaus] [-o DIRECTORY]

DESCRIPTION

options:
  -h, --help                        show this help message and exit
  -q, --quiet                       do not print a banner
  -c FILE, --config FILE            config file (default: "config/config.yml")
  --disable-shodan                  disable querying Shodan
  --disable-feodotracker            disable querying Feodo Tracker
  --disable-urlhaus                 disable querying URLhaus
  -o DIRECTORY, --output DIRECTORY  output directory (default: "reports/")
```

### Examples







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