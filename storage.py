# storage.py
from __future__ import annotations

import datetime
import sqlite3
from typing import List, Optional

DB_PATH = "hot_wallet.db"
MAX_ACCOUNTS_PER_WALLET = 5


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row["name"] for row in rows]


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    wallet_cols = _table_columns(conn, "wallets")
    if wallet_cols and "name" not in wallet_cols:
        conn.execute("DROP TABLE IF EXISTS wallets")
        conn.execute("DROP TABLE IF EXISTS accounts")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE (user_id, name)
        )
    """)

    wallet_cols = _table_columns(conn, "wallets")
    if "encrypted_mnemonic" not in wallet_cols:
        conn.execute(
            "ALTER TABLE wallets ADD COLUMN encrypted_mnemonic TEXT"
        )

    account_cols = _table_columns(conn, "accounts")
    if account_cols and ("name" not in account_cols or "network" not in account_cols):
        conn.execute("DROP TABLE IF EXISTS accounts")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            wallet_id TEXT NOT NULL,
            name TEXT NOT NULL,
            network TEXT NOT NULL,
            address TEXT UNIQUE NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (wallet_id) REFERENCES wallets(id),
            UNIQUE (wallet_id, name)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    if "wallet_id" not in _table_columns(conn, "webauthn_credentials"):
        # NULL means captured at signup and not yet bound to a wallet.
        conn.execute("ALTER TABLE webauthn_credentials ADD COLUMN wallet_id TEXT")
    conn.commit()
    conn.close()


def create_user(
    user_id: str,
    email: str,
    hashed_password: str,
    credential: Optional[dict] = None,
) -> dict:
    conn = get_connection()
    created_at = datetime.datetime.utcnow().isoformat()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (id, email, hashed_password, created_at) VALUES (?, ?, ?, ?)",
                (user_id, email, hashed_password, created_at),
            )
            if credential is not None:
                conn.execute(
                    """
                    INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        credential["id"],
                        user_id,
                        credential["public_key"],
                        credential["sign_count"],
                        created_at,
                    ),
                )
    finally:
        conn.close()
    return {
        "id": user_id,
        "email": email,
        "hashed_password": hashed_password,
        "created_at": created_at,
    }


def get_user_by_email(email: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_email(user_id: str, email: str) -> None:
    conn = get_connection()
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    conn.commit()
    conn.close()


def update_user_password(user_id: str, hashed_password: str) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE users SET hashed_password = ? WHERE id = ?",
        (hashed_password, user_id),
    )
    conn.commit()
    conn.close()


def add_webauthn_credential(
    credential_id: str,
    user_id: str,
    public_key: str,
    sign_count: int,
    wallet_id: Optional[str] = None,
) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO webauthn_credentials (id, user_id, wallet_id, public_key, sign_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            credential_id,
            user_id,
            wallet_id,
            public_key,
            sign_count,
            datetime.datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def list_webauthn_credentials(user_id: str) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_wallet_credentials(wallet_id: str) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM webauthn_credentials WHERE wallet_id = ? ORDER BY created_at ASC",
        (wallet_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def bind_unassigned_credentials(user_id: str, wallet_id: str) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE webauthn_credentials SET wallet_id = ? WHERE user_id = ? AND wallet_id IS NULL",
        (wallet_id, user_id),
    )
    conn.commit()
    conn.close()


def update_webauthn_sign_count(credential_id: str, sign_count: int) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?",
        (sign_count, credential_id),
    )
    conn.commit()
    conn.close()


def delete_wallet(wallet_id: str) -> List[str]:
    """Delete a wallet, its accounts and its passkeys; returns the revoked credential IDs."""
    conn = get_connection()
    try:
        with conn:
            revoked = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM webauthn_credentials WHERE wallet_id = ?", (wallet_id,)
                ).fetchall()
            ]
            conn.execute("DELETE FROM webauthn_credentials WHERE wallet_id = ?", (wallet_id,))
            conn.execute("DELETE FROM accounts WHERE wallet_id = ?", (wallet_id,))
            conn.execute("DELETE FROM wallets WHERE id = ?", (wallet_id,))
    finally:
        conn.close()
    return revoked


def create_named_wallet(
    wallet_id: str,
    user_id: str,
    name: str,
    encrypted_mnemonic: str,
) -> dict:
    conn = get_connection()
    created_at = datetime.datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO wallets (id, user_id, name, created_at, encrypted_mnemonic)
        VALUES (?, ?, ?, ?, ?)
        """,
        (wallet_id, user_id, name, created_at, encrypted_mnemonic),
    )
    conn.commit()
    conn.close()
    return {
        "id": wallet_id,
        "user_id": user_id,
        "name": name,
        "created_at": created_at,
        "encrypted_mnemonic": encrypted_mnemonic,
    }


def set_wallet_mnemonic(wallet_id: str, encrypted_mnemonic: str) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE wallets SET encrypted_mnemonic = ? WHERE id = ?",
        (encrypted_mnemonic, wallet_id),
    )
    conn.commit()
    conn.close()


def list_wallets_by_user(user_id: str) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT w.*,
               (SELECT COUNT(*) FROM accounts a WHERE a.wallet_id = w.id) AS account_count
        FROM wallets w
        WHERE w.user_id = ?
        ORDER BY w.created_at ASC
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_wallet_by_id(wallet_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM wallets WHERE id = ?", (wallet_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_wallet_for_user(wallet_id: str, user_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM wallets WHERE id = ? AND user_id = ?",
        (wallet_id, user_id),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def count_accounts(wallet_id: str) -> int:
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM accounts WHERE wallet_id = ?",
        (wallet_id,),
    ).fetchone()
    conn.close()
    return int(row["count"])


def list_accounts(wallet_id: str) -> List[dict]:
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id, wallet_id, name, network, address, created_at
        FROM accounts
        WHERE wallet_id = ?
        ORDER BY created_at ASC
        """,
        (wallet_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_account_by_id(account_id: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_account_row(
    account_id: str,
    wallet_id: str,
    name: str,
    network: str,
    address: str,
    encrypted_private_key: str,
) -> dict:
    conn = get_connection()
    created_at = datetime.datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO accounts (
            id, wallet_id, name, network, address, encrypted_private_key, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (account_id, wallet_id, name, network, address, encrypted_private_key, created_at),
    )
    conn.commit()
    conn.close()
    return {
        "id": account_id,
        "wallet_id": wallet_id,
        "name": name,
        "network": network,
        "address": address,
        "created_at": created_at,
    }
