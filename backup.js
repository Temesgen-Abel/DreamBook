const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const backupDir = path.join(__dirname, "backups");

if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir);
}

const date = new Date().toISOString().split("T")[0];
const file = `${backupDir}/dreambook_${date}.sql`;

const cmd = `pg_dump "${process.env.BACKUP_DATABASE_URL}" > ${file}`;

exec(cmd, (err) => {
  if (err) {
    console.error("❌ Backup failed:", err);
  } else {
    console.log("✅ Backup created:", file);
  }
});
