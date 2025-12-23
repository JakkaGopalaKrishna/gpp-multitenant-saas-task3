const fs = require('fs');
const path = require('path');
const pool = require('../src/config/database');

async function runMigrations() {
  const migrationsDir = __dirname;
  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const filePath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(filePath, 'utf8');
    
    try {
      await pool.query(sql);
      console.log(`✓ Executed migration: ${file}`);
    } catch (error) {
      console.error(`✗ Migration failed: ${file}`, error.message);
      throw error;
    }
  }
  
  console.log('✓ All migrations completed successfully');
  process.exit(0);
}

runMigrations().catch(error => {
  console.error('Migration error:', error);
  process.exit(1);
});
