
import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';

const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

export const db = new sqlite3.Database(path.join(dataDir, 'app.sqlite'));

export function run(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

export function all(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function(err, rows) {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

export function get(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function(err, row) {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
