require 'sqlite3'
require 'bcrypt'

DB = SQLite3::Database.new("users.db")

DB.execute <<-SQL
  CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    name TEXT,
    password_hash TEXT,
    reset_token TEXT,
    reset_sent_at TEXT
  );
SQL

# Insert test user (password is 'test123')
hashed_pw = BCrypt::Password.create("test123")
DB.execute("INSERT OR REPLACE INTO users (email, name, password_hash) VALUES (?, ?, ?)",
           ["test@gmail.com", "test", hashed_pw])
