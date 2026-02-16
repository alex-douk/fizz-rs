#!/bin/bash
cd fizz
python3 build/fbcode_builder/getdeps.py --allow-system-packages install-system-deps --recursive fizz
python3 build/fbcode_builder/getdeps.py --scratch-path ../fizz-install --allow-system-packages build fizz
cd ..
