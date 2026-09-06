#!/usr/bin/env bash
# build.sh — Render build script for TornSpy / ThreatLens SOC Simulation
# Runs automatically during every Render deploy.
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --noinput
python manage.py migrate
