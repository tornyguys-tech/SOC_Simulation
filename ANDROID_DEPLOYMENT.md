# Android Deployment

TornSpy runs on Android through Termux with a single startup command:

```bash
bash start_tornspy.sh
```

## Required Packages

Install these inside Termux:

```bash
pkg update && pkg upgrade
pkg install python git
```

Optional but recommended:

```bash
termux-wake-lock
```

## Install The Project

```bash
git clone <your-repo-url> tornspy
cd tornspy
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Start TornSpy

From the project root:

```bash
bash start_tornspy.sh
```

This starts:

- APScheduler in the background
- Django on `0.0.0.0:8000`
- log files under `logs/`

## Runtime Files

The startup script creates these automatically:

- `logs/scheduler.log`
- `logs/server.log`
- `logs/scheduler.pid`
- `logs/server.pid`

## Health Check

Use this endpoint to confirm the app is alive:

```bash
/health/
```

It returns:

```json
{"status":"ok"}
```

## Status Command

Check the local runtime state with:

```bash
python manage.py status
```

It reports:

- Scheduler running or stopped
- Server running or stopped
- Database status
- Campaign count
- Snapshot count

## Auto-Start With Termux:Boot

1. Install the `Termux:Boot` app.
2. Create the boot directory if needed:

```bash
mkdir -p ~/.termux/boot
```

3. Create a boot script named `start_tornspy.sh` inside `~/.termux/boot/` that runs:

```bash
cd ~/tornspy && bash start_tornspy.sh
```

4. Make sure the script is executable:

```bash
chmod +x ~/.termux/boot/start_tornspy.sh
```

## Battery Optimization

For reliable long-running operation:

- Disable battery optimization for Termux
- Allow background activity
- Keep the phone plugged in when possible
- Use `termux-wake-lock` to reduce sleep interruptions

## Notes

- Keep `TORN_API_KEY` available in the environment or in your shell profile.
- SQLite is the intended database for Android.
- Do not start a second copy of the app while one is already running.