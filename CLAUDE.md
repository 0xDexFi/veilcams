# VeilCams - Development Notes

## Setup

- Development happens on Windows
- VeilCams runs on a separate Linux VM where the user pulls from GitHub and runs scans

## Deploying changes to Linux VM

After pushing changes from Windows, the user runs these commands on their Linux VM (~/veilcams):

```bash
git checkout veilcams
git pull
chmod +x veilcams
docker compose down
docker compose build
./veilcams start
```

Do NOT suggest any other commands. Do NOT add flags like `--no-cache`, `REBUILD=true`, `docker compose up -d`, or anything the user has not used before.
