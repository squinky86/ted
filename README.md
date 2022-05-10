# TED NuGet

Ted NuGet (Testing External Dependencies in NuGet) performs open sources checks against a NuGet packages.config file.

## Installation

You may want to create a virtual environment to install dependencies by following the below process:

### Windows
```bash
$ py -m venv env
$ .\env\Scripts\activate
$ pip install -r requirements.txt
```

### Linux
```bash
$ python3 -m venv env
$ source env/bin/activate
$ pip install -r requirements.txt
```

Once dependencies have been installed, you can run it as a Python3 script.

### Linux
```bash
$ python3 ted.py [options] <path>
```

### Windows
```bash
$ py ted.py [options] <path>
```

For help use "-h" flag.

## Authors/Contributors

* Jon Hood (squinky86)
* crook3dfingers

## License

[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)
