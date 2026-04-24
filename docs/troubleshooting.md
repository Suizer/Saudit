# Troubleshooting

## Installation troubleshooting
- `Fatal error from pip prevented installation.`
- `ERROR: No matching distribution found for saudit`
- `bash: /home/user/.local/bin/saudit: /home/user/.local/pipx/venvs/saudit/bin/python: bad interpreter`

If you get errors resembling any of the above, it's probably because your Python version is too old. To install a newer version (3.9+ is required), you will need to do something like this:
```bash
# install a newer version of python
sudo apt install python3.9 python3.9-venv
# install pipx
python3.9 -m pip install --user pipx
# add pipx to your path
python3.9 -m pipx ensurepath
# reboot
reboot
# install saudit
python3.9 -m pipx install saudit
# run saudit
saudit --help
```

## `ModuleNotFoundError`
If you run into a `ModuleNotFoundError`, try running your `saudit` command again with `--force-deps`. This will repair your modules' Python dependencies.

## Regenerate Config
As a troubleshooting step it is sometimes useful to clear out your older configs and let SAUDIT generate new ones. This will ensure that new defaults are property restored, etc.
```bash
# make a backup of the old configs
mv ~/.config/saudit ~/.config/saudit.bak

# generate new configs
saudit
```
