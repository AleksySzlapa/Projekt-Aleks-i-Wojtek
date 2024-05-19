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
    status INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP);''')

cur.execute('''
    CREATE TABLE friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_1 INTEGER NOT NULL,
    user_2 INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_1) REFERENCES users(id),
    FOREIGN KEY (user_2) REFERENCES users(id));''')

cur.execute('''
    CREATE TABLE friends_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_1 INTEGER NOT NULL,
    user_2 INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    isWaiting INTEGER NOT NULL DEFAULT 1,
    isAccept INTEGER NULL DEFAULT NULL,
    FOREIGN KEY (user_1) REFERENCES users(id),
    FOREIGN KEY (user_2) REFERENCES users(id));''')

cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user', ph.hash('pass')))
cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('user2', ph.hash('pass')))

cur.execute('INSERT INTO friends (user_1, user_2) VALUES (?, ?)', ('1', '2'))

conn.commit()
cur.close()
conn.close()