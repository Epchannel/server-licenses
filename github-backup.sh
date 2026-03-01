#!/bin/bash
# Daily GitHub backup script for License Server
cd /home/ubuntu/.gemini/antigravity/scratch/gdrive-website/license-server-backup_20260122_185507

# Add all changes
git add -A

# Commit with timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
git commit -m "Auto backup: ${TIMESTAMP}" 2>/dev/null

# Push (only if there are new commits)
if [ $? -eq 0 ]; then
    git push origin main 2>&1
    echo "[${TIMESTAMP}] Backup pushed successfully" >> /home/ubuntu/backup.log
else
    echo "[${TIMESTAMP}] No changes to backup" >> /home/ubuntu/backup.log
fi
