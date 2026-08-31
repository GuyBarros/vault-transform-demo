podman compose -f docker/docker-compose.yml up -d
bash scripts/setup_vault.sh
bash scripts/seed_creds.sh
bash run_demo.sh