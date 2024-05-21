import sqlite3
from argon2 import PasswordHasher
conn = sqlite3.connect('cool_database.db')

cur = conn.cursor()
ph = PasswordHasher()
cur.execute('''
    CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP);''')


cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user', ph.hash('pass')))
cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user2', ph.hash('pass')))

conn.commit()
cur.close()
conn.close()