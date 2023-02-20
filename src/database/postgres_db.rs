// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.client <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.client> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
use std::cell::RefCell;
use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hash_types::Txid;
use bitcoin::{OutPoint, Script, Transaction, TxOut};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use sha256::digest;

use crate::database::{BatchDatabase, BatchOperations, Database, SyncTime};
use crate::types::*;
use crate::Error;

use postgres::{Client, NoTls};

pub type PostgresResult<T, E = postgres::Error> = Result<T, E>;

static MIGRATIONS: &[&str] = &[
    "CREATE TABLE version (version INTEGER);",
    "INSERT INTO version VALUES (1);",
    "CREATE TABLE script_pubkeys (keychain TEXT, child INTEGER, script BYTEA);",
    "CREATE INDEX idx_keychain_child ON script_pubkeys(keychain, child);",
    "CREATE INDEX idx_script ON script_pubkeys(script);",
    "CREATE TABLE utxos (value BIGINT, keychain TEXT, vout INTEGER, txid BYTEA, script BYTEA);",
    "CREATE INDEX idx_txid_vout ON utxos(txid, vout);",
    "CREATE TABLE transactions (txid BYTEA, raw_tx BYTEA);",
    "CREATE INDEX idx_txid ON transactions(txid);",
    "CREATE TABLE transaction_details (txid BYTEA, timestamp BIGINT, received BIGINT, sent BIGINT, fee BIGINT, height INTEGER, verified INTEGER DEFAULT 0);",
    "CREATE INDEX idx_txdetails_txid ON transaction_details(txid);",
    "CREATE TABLE last_derivation_indices (keychain TEXT, value INTEGER);",
    "CREATE UNIQUE INDEX idx_indices_keychain ON last_derivation_indices(keychain);",
    "CREATE TABLE checksums (keychain TEXT, checksum BYTEA);",
    "CREATE INDEX idx_checksums_keychain ON checksums(keychain);",
    "CREATE TABLE sync_time (id INTEGER PRIMARY KEY, height INTEGER, timestamp BIGINT);",
    "ALTER TABLE transaction_details RENAME TO transaction_details_old;",
    "CREATE TABLE transaction_details (txid BYTEA, timestamp BIGINT, received BIGINT, sent BIGINT, fee BIGINT, height INTEGER);",
    "INSERT INTO transaction_details SELECT txid, timestamp, received, sent, fee, height FROM transaction_details_old;",
    "DROP TABLE transaction_details_old;",
    "ALTER TABLE utxos ADD COLUMN is_spent BOOL;",
    // drop all data due to possible inconsistencies with duplicate utxos, re-sync required
    "DELETE FROM checksums;",
    "DELETE FROM last_derivation_indices;",
    "DELETE FROM script_pubkeys;",
    "DELETE FROM sync_time;",
    "DELETE FROM transaction_details;",
    "DELETE FROM transactions;",
    "DELETE FROM utxos;",
    "DROP INDEX idx_txid_vout;",
    "CREATE UNIQUE INDEX idx_utxos_txid_vout ON utxos(txid, vout);",
    "ALTER TABLE utxos RENAME TO utxos_old;",
    "CREATE TABLE utxos (value BIGINT, keychain TEXT, vout INTEGER, txid BYTEA, script BYTEA, is_spent BOOL DEFAULT FALSE);",
    "INSERT INTO utxos SELECT value, keychain, vout, txid, script, is_spent FROM utxos_old;",
    "DROP TABLE utxos_old;",
    "CREATE UNIQUE INDEX idx_utxos_txid_vout ON utxos(txid, vout);",
    // Fix issue https://github.com/bitcoindevkit/bdk/issues/801: drop duplicated script_pubkeys
    "ALTER TABLE script_pubkeys RENAME TO script_pubkeys_old;",
    "DROP INDEX idx_keychain_child;",
    "DROP INDEX idx_script;",
    "CREATE TABLE script_pubkeys (keychain TEXT, child INTEGER, script BYTEA);",
    "CREATE INDEX idx_keychain_child ON script_pubkeys(keychain, child);",
    "CREATE INDEX idx_script ON script_pubkeys(script);",
    "CREATE UNIQUE INDEX idx_script_pks_unique ON script_pubkeys(keychain, child);",
    // Postgres upsert: https://www.postgresqltutorial.com/postgresql-tutorial/postgresql-upsert/
    "INSERT INTO script_pubkeys (keychain, child, script) SELECT keychain, child, script FROM script_pubkeys_old ON CONFLICT (keychain, child) DO UPDATE SET keychain = EXCLUDED.keychain, child = EXCLUDED.child, script = EXCLUDED.script;",
    "DROP TABLE script_pubkeys_old;"
];

/// Postgres database stored remotely..
/// [`crate::database`]
pub struct PostgresDatabase {
    client: RefCell<Client>,
    uri: String,
    database: String,
    descriptor: String,
    tls_mode: bool,
}

impl fmt::Debug for PostgresDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresDatabase")
            .field("uri", &self.uri)
            .field("database", &self.database)
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

/// A wallet transaction
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TransactionDetailsInternal {
    /// Optional transaction
    pub transaction: Option<Transaction>,
    /// Transaction id
    pub txid: Txid,

    /// Received value (sats)
    /// Sum of owned outputs of this transaction.
    pub received: i64,
    /// Sent value (sats)
    /// Sum of owned inputs of this transaction.
    pub sent: i64,
    /// Fee value (sats) if confirmed.
    /// The availability of the fee depends on the backend. It's never `None` with an Electrum
    /// Server backend, but it could be `None` with a Bitcoin RPC node without txindex that receive
    /// funds while offline.
    pub fee: Option<i64>,
    /// If the transaction is confirmed, contains height and timestamp of the block containing the
    /// transaction, unconfirmed transaction contains `None`.
    pub confirmation_time: Option<BlockTimeInternal>,
}

impl TryFrom<&TransactionDetails> for TransactionDetailsInternal {
    type Error = Error;

    fn try_from(value: &TransactionDetails) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction: value.transaction.clone(),
            txid: value.txid,
            received: value.received as i64,
            sent: value.sent as i64,
            fee: value.fee.map(|v| v as i64),
            confirmation_time: match &value.confirmation_time {
                Some(v) => Some(v.try_into()?),
                None => None,
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
struct BlockTimeInternal {
    /// confirmation block height
    height: i32,
    /// confirmation block timestamp
    timestamp: i64,
}

impl TryFrom<&BlockTime> for BlockTimeInternal {
    type Error = Error;

    fn try_from(value: &BlockTime) -> Result<Self, Self::Error> {
        Ok(Self {
            height: value.height as i32,
            timestamp: value.timestamp as i64,
        })
    }
}

impl PostgresDatabase {
    /// Instantiates a new Postgres Database instance.
    ///
    /// Creates a connection to the requested database. The full connection
    /// string is combination of `uri` and `database + descriptor`.
    ///
    /// Attempts to connect to the specified database, if such database
    /// doesn't exist, creates it via the base PostgreSQL connection.
    pub fn new(uri: &str, database: &str, descriptor: &str, tls_mode: bool) -> Result<Self, Error> {
        let descriptor_hash = digest(descriptor);

        match Self::connect(uri, database, descriptor, tls_mode) {
            Ok(mut c) => {
                migrate(&mut c)?;
                Ok(Self {
                    client: RefCell::new(c),
                    uri: uri.to_string(),
                    database: database.to_string(),
                    descriptor: descriptor.to_string(),
                    tls_mode,
                })
            }
            Err(Error::Postgres(e)) => match e.code() {
                Some(state) if state == &postgres::error::SqlState::UNDEFINED_DATABASE => {
                    let mut conn =
                        Self::create_new_database(uri, database, &descriptor_hash, tls_mode)?;
                    migrate(&mut conn)?;
                    Ok(Self {
                        client: RefCell::new(conn),
                        uri: uri.to_string(),
                        database: database.to_string(),
                        descriptor: descriptor.to_string(),
                        tls_mode,
                    })
                }
                _ => Err(e.into()),
            },
            Err(e) => Err(e),
        }
    }

    /// Creates the new database and returns connection to it.
    ///
    /// Due to potential race, the database could have been created via
    /// concurrent connection. This is fine, as long as we treat the database
    /// duplication error as `Ok`.
    fn create_new_database(
        uri: &str,
        database: &str,
        descriptor: &str,
        tls_mode: bool,
    ) -> Result<Client, Error> {
        let mut client = if tls_mode {
            let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| {
                Error::Generic(format!("Failed to create SSL connection builder: {e}"))
            })?;
            builder.set_verify(SslVerifyMode::NONE);

            Client::connect(uri, MakeTlsConnector::new(builder.build()))?
        } else {
            Client::connect(uri, postgres::tls::NoTls)?
        };

        match client.execute(&format!("CREATE DATABASE {database}_{descriptor}"), &[]) {
            Ok(_) => Self::connect(uri, database, descriptor, tls_mode),
            Err(e) => match e.code() {
                Some(state) if state == &postgres::error::SqlState::DUPLICATE_DATABASE => {
                    Self::connect(uri, database, descriptor, tls_mode)
                }
                _ => Err(e.into()),
            },
        }
    }

    fn connect(
        uri: &str,
        database: &str,
        descriptor: &str,
        tls_mode: bool,
    ) -> Result<Client, Error> {
        if tls_mode {
            let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| {
                Error::Generic(format!("Failed to create SSL connection builder: {e}"))
            })?;
            builder.set_verify(SslVerifyMode::NONE);

            Ok(Client::connect(
                &format!("{uri}/{database}_{descriptor}?sslmode=require"),
                MakeTlsConnector::new(builder.build()),
            )?)
        } else {
            Ok(Client::connect(
                &format!("{uri}/{database}_{descriptor}"),
                NoTls,
            )?)
        }
    }

    fn insert_script_pubkey(
        &self,
        keychain: String,
        child: u32,
        script: &[u8],
    ) -> Result<(), Error> {
        let statement = self.client.borrow_mut().prepare(
            "INSERT INTO script_pubkeys (keychain, child, script) VALUES ($1, $2, $3) ON CONFLICT (keychain, child) DO UPDATE SET keychain = EXCLUDED.keychain, child = EXCLUDED.child, script = EXCLUDED.script;",
        )?;
        self.client
            .borrow_mut()
            .execute(&statement, &[&keychain, &(child as i32), &script])?;

        Ok(())
    }

    fn insert_utxo(
        &self,
        value: u64,
        keychain: String,
        vout: u32,
        txid: &[u8],
        script: &[u8],
        is_spent: bool,
    ) -> Result<(), Error> {
        let statement = self.client.borrow_mut().prepare("INSERT INTO utxos (value, keychain, vout, txid, script, is_spent) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT(txid, vout) DO UPDATE SET value=$1, keychain=$2, script=$5, is_spent=$6")?;
        self.client.borrow_mut().execute(
            &statement,
            &[
                &(value as i64),
                &keychain,
                &&(vout as i32),
                &txid,
                &script,
                &is_spent,
            ],
        )?;

        Ok(())
    }

    fn insert_transaction(&self, txid: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("INSERT INTO transactions (txid, raw_tx) VALUES ($1, $2)")?;
        self.client
            .borrow_mut()
            .execute(&statement, &[&txid, &raw_tx])?;

        Ok(())
    }

    fn update_transaction(&self, txid: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("UPDATE transactions SET raw_tx=$2 WHERE txid=$1")?;

        self.client
            .borrow_mut()
            .execute(&statement, &[&txid, &raw_tx])?;

        Ok(())
    }

    fn insert_transaction_details(&self, transaction: &TransactionDetails) -> Result<(), Error> {
        let transaction: TransactionDetailsInternal = transaction.try_into()?;
        let (timestamp, height) = match &transaction.confirmation_time {
            Some(confirmation_time) => (
                Some(confirmation_time.timestamp),
                Some(confirmation_time.height),
            ),
            None => (None, None),
        };

        let txid: &[u8] = &transaction.txid;
        let statement = self.client.borrow_mut().prepare("INSERT INTO transaction_details (txid, timestamp, received, sent, fee, height) VALUES ($1, $2, $3, $4, $5, $6)")?;
        self.client.borrow_mut().execute(
            &statement,
            &[
                &txid,
                &timestamp,
                &transaction.received,
                &transaction.sent,
                &transaction.fee,
                &height,
            ],
        )?;

        Ok(())
    }

    fn update_transaction_details(&self, transaction: &TransactionDetails) -> Result<(), Error> {
        let transaction: TransactionDetailsInternal = transaction.try_into()?;
        let (timestamp, height) = match &transaction.confirmation_time {
            Some(confirmation_time) => (
                Some(confirmation_time.timestamp),
                Some(confirmation_time.height),
            ),
            None => (None, None),
        };

        let txid: &[u8] = &transaction.txid;
        let statement = self.client.borrow_mut().prepare("UPDATE transaction_details SET timestamp=$2, received=$3, sent=$4, fee=$5, height=$6 WHERE txid=$1;")?;
        self.client.borrow_mut().execute(
            &statement,
            &[
                &txid,
                &timestamp,
                &transaction.received,
                &transaction.sent,
                &transaction.fee,
                &height,
            ],
        )?;

        Ok(())
    }

    fn insert_last_derivation_index(&self, keychain: String, value: u32) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("INSERT INTO last_derivation_indices (keychain, value) VALUES ($1, $2)")?;

        self.client
            .borrow_mut()
            .execute(&statement, &[&keychain, &(value as i32)])?;

        Ok(())
    }

    fn insert_checksum(&self, keychain: String, checksum: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("INSERT INTO checksums (keychain, checksum) VALUES ($1, $2)")?;
        self.client
            .borrow_mut()
            .execute(&statement, &[&keychain, &checksum])?;

        Ok(())
    }

    fn update_last_derivation_index(&self, keychain: String, value: u32) -> Result<(), Error> {
        let statement = self.client.borrow_mut().prepare(
            "INSERT INTO last_derivation_indices (keychain, value) VALUES ($1, $2) ON CONFLICT(keychain) DO UPDATE SET value=$2",
        )?;

        self.client
            .borrow_mut()
            .execute(&statement, &[&keychain, &(value as i32)])?;

        Ok(())
    }

    fn update_sync_time(&self, data: SyncTime) -> Result<(), Error> {
        let block = &data.block_time;
        let block: BlockTimeInternal = block.try_into()?;
        let statement = self.client.borrow_mut().prepare(
            "INSERT INTO sync_time (id, height, timestamp) VALUES (0, $1, $2) ON CONFLICT(id) DO UPDATE SET height=$1, timestamp=$2",
        )?;

        self.client
            .borrow_mut()
            .execute(&statement, &[&block.height, &block.timestamp])?;

        Ok(())
    }

    fn select_script_pubkeys(&self) -> Result<Vec<Script>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT script FROM script_pubkeys")?;
        let mut scripts: Vec<Script> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[])?;
        for row in rows {
            let raw_script: Vec<u8> = row.get(0);
            scripts.push(raw_script.into());
        }

        Ok(scripts)
    }

    fn select_script_pubkeys_by_keychain(&self, keychain: String) -> Result<Vec<Script>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT script FROM script_pubkeys WHERE keychain=$1")?;
        let mut scripts: Vec<Script> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[&keychain])?;
        for row in rows {
            let raw_script: Vec<u8> = row.get(0);
            scripts.push(raw_script.into());
        }

        Ok(scripts)
    }

    fn select_script_pubkey_by_path(
        &self,
        keychain: String,
        child: u32,
    ) -> Result<Option<Script>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT script FROM script_pubkeys WHERE keychain=$1 AND child=$2")?;
        let rows = self
            .client
            .borrow_mut()
            .query(&statement, &[&keychain, &(child as i32)])?;

        match rows.first() {
            Some(row) => {
                let script: Vec<u8> = row.get(0);
                let script: Script = script.into();
                Ok(Some(script))
            }
            None => Ok(None),
        }
    }

    fn select_script_pubkey_by_script(
        &self,
        script: &[u8],
    ) -> Result<Option<(KeychainKind, u32)>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT keychain, child FROM script_pubkeys WHERE script=$1")?;
        let rows = self.client.borrow_mut().query(&statement, &[&script])?;
        match rows.first() {
            Some(row) => {
                let keychain: String = row.get(0);
                let keychain: KeychainKind = serde_json::from_str(&keychain)?;
                let child: i32 = row.get(1);
                Ok(Some((keychain, child as u32)))
            }
            None => Ok(None),
        }
    }

    fn select_utxos(&self) -> Result<Vec<LocalUtxo>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT value, keychain, vout, txid, script, is_spent FROM utxos")?;
        let mut utxos: Vec<LocalUtxo> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[])?;
        for row in rows {
            let value: i64 = row.get(0);
            let keychain: String = row.get(1);
            let vout: i32 = row.get(2);
            let txid: Vec<u8> = row.get(3);
            let script: Vec<u8> = row.get(4);
            let is_spent: bool = row.get(5);

            let keychain: KeychainKind = serde_json::from_str(&keychain)?;

            utxos.push(LocalUtxo {
                outpoint: OutPoint::new(deserialize(&txid)?, vout as u32),
                txout: TxOut {
                    value: value as u64,
                    script_pubkey: script.into(),
                },
                keychain,
                is_spent,
            })
        }

        Ok(utxos)
    }

    fn select_utxo_by_outpoint(&self, txid: &[u8], vout: u32) -> Result<Option<LocalUtxo>, Error> {
        let statement = self.client.borrow_mut().prepare(
            "SELECT value, keychain, script, is_spent FROM utxos WHERE txid=$1 AND vout=$2",
        )?;
        let rows = self
            .client
            .borrow_mut()
            .query(&statement, &[&txid, &(vout as i32)])?;
        match rows.first() {
            Some(row) => {
                let value: i64 = row.get(0);
                let keychain: String = row.get(1);
                let keychain: KeychainKind = serde_json::from_str(&keychain)?;
                let script: Vec<u8> = row.get(2);
                let script_pubkey: Script = script.into();
                let is_spent: bool = row.get(3);

                Ok(Some(LocalUtxo {
                    outpoint: OutPoint::new(deserialize(txid)?, vout),
                    txout: TxOut {
                        value: value as u64,
                        script_pubkey,
                    },
                    keychain,
                    is_spent,
                }))
            }
            None => Ok(None),
        }
    }

    fn select_transactions(&self) -> Result<Vec<Transaction>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT raw_tx FROM transactions")?;
        let mut txs: Vec<Transaction> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[])?;
        for row in rows {
            let raw_tx: Vec<u8> = row.get(0);
            let tx: Transaction = deserialize(&raw_tx)?;
            txs.push(tx);
        }
        Ok(txs)
    }

    fn select_transaction_by_txid(&self, txid: &[u8]) -> Result<Option<Transaction>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT raw_tx FROM transactions WHERE txid=$1")?;
        let rows = self.client.borrow_mut().query(&statement, &[&txid])?;
        match rows.first() {
            Some(row) => {
                let raw_tx: Vec<u8> = row.get(0);
                let tx: Transaction = deserialize(&raw_tx)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn select_transaction_details_with_raw(&self) -> Result<Vec<TransactionDetails>, Error> {
        let statement = self.client.borrow_mut().prepare("SELECT transaction_details.txid, transaction_details.timestamp, transaction_details.received, transaction_details.sent, transaction_details.fee, transaction_details.height, transactions.raw_tx FROM transaction_details, transactions WHERE transaction_details.txid = transactions.txid")?;
        let mut transaction_details: Vec<TransactionDetails> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[])?;
        for row in rows {
            let txid: Vec<u8> = row.get(0);
            let txid: Txid = deserialize(&txid)?;
            let timestamp: Option<i64> = row.get(1);
            let received: i64 = row.get(2);
            let sent: i64 = row.get(3);
            let fee: Option<i64> = row.get(4);
            let height: Option<i32> = row.get(5);
            let raw_tx: Option<Vec<u8>> = row.get(6);
            let tx: Option<Transaction> = match raw_tx {
                Some(raw_tx) => {
                    let tx: Transaction = deserialize(&raw_tx)?;
                    Some(tx)
                }
                None => None,
            };

            let confirmation_time = match (height, timestamp) {
                (Some(height), Some(timestamp)) => Some(BlockTime {
                    height: height as u32,
                    timestamp: timestamp as u64,
                }),
                _ => None,
            };

            transaction_details.push(TransactionDetails {
                transaction: tx,
                txid,
                received: received as u64,
                sent: sent as u64,
                fee: fee.map(|v| v as u64),
                confirmation_time,
            });
        }
        Ok(transaction_details)
    }

    fn select_transaction_details(&self) -> Result<Vec<TransactionDetails>, Error> {
        let statement = self.client.borrow_mut().prepare(
            "SELECT txid, timestamp, received, sent, fee, height FROM transaction_details",
        )?;
        let mut transaction_details: Vec<TransactionDetails> = vec![];
        let rows = self.client.borrow_mut().query(&statement, &[])?;
        for row in rows {
            let txid: Vec<u8> = row.get(0);
            let txid: Txid = deserialize(&txid)?;
            let timestamp: Option<i64> = row.get(1);
            let received: i64 = row.get(2);
            let sent: i64 = row.get(3);
            let fee: Option<i64> = row.get(4);
            let height: Option<i32> = row.get(5);

            let confirmation_time = match (height, timestamp) {
                (Some(height), Some(timestamp)) => Some(BlockTime {
                    height: height as u32,
                    timestamp: timestamp as u64,
                }),
                _ => None,
            };

            transaction_details.push(TransactionDetails {
                transaction: None,
                txid,
                received: received as u64,
                sent: sent as u64,
                fee: fee.map(|v| v as u64),
                confirmation_time,
            });
        }
        Ok(transaction_details)
    }

    fn select_transaction_details_by_txid(
        &self,
        txid: &[u8],
    ) -> Result<Option<TransactionDetails>, Error> {
        let statement = self.client.borrow_mut().prepare("SELECT transaction_details.timestamp, transaction_details.received, transaction_details.sent, transaction_details.fee, transaction_details.height, transactions.raw_tx FROM transaction_details, transactions WHERE transaction_details.txid=transactions.txid AND transaction_details.txid=$1")?;
        let rows = self.client.borrow_mut().query(&statement, &[&txid])?;
        match rows.first() {
            Some(row) => {
                let timestamp: Option<i64> = row.get(0);
                let received: i64 = row.get(1);
                let sent: i64 = row.get(2);
                let fee: Option<i64> = row.get(3);
                let height: Option<i32> = row.get(4);

                let raw_tx: Option<Vec<u8>> = row.get(5);
                let tx: Option<Transaction> = match raw_tx {
                    Some(raw_tx) => {
                        let tx: Transaction = deserialize(&raw_tx)?;
                        Some(tx)
                    }
                    None => None,
                };

                let confirmation_time = match (height, timestamp) {
                    (Some(height), Some(timestamp)) => Some(BlockTime {
                        height: height as u32,
                        timestamp: timestamp as u64,
                    }),
                    _ => None,
                };

                Ok(Some(TransactionDetails {
                    transaction: tx,
                    txid: deserialize(txid)?,
                    received: received as u64,
                    sent: sent as u64,
                    fee: fee.map(|v| v as u64),
                    confirmation_time,
                }))
            }
            None => Ok(None),
        }
    }

    fn select_last_derivation_index_by_keychain(
        &self,
        keychain: String,
    ) -> Result<Option<u32>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT value FROM last_derivation_indices WHERE keychain=$1")?;
        let rows = self.client.borrow_mut().query(&statement, &[&keychain])?;
        match rows.first() {
            Some(row) => {
                let value: i32 = row.get(0);
                Ok(Some(value as u32))
            }
            None => Ok(None),
        }
    }

    fn select_sync_time(&self) -> Result<Option<SyncTime>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT height, timestamp FROM sync_time WHERE id = 0")?;
        let rows = self.client.borrow_mut().query(&statement, &[])?;

        if let Some(row) = rows.first() {
            let h: i32 = row.get(0);
            let t: i64 = row.get(1);
            Ok(Some(SyncTime {
                block_time: BlockTime {
                    height: h as u32,
                    timestamp: t as u64,
                },
            }))
        } else {
            Ok(None)
        }
    }

    fn select_checksum_by_keychain(&self, keychain: String) -> Result<Option<Vec<u8>>, Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("SELECT checksum FROM checksums WHERE keychain=$1")?;
        let rows = self.client.borrow_mut().query(&statement, &[&keychain])?;

        match rows.first() {
            Some(row) => {
                let checksum: Vec<u8> = row.get(0);
                Ok(Some(checksum))
            }
            None => Ok(None),
        }
    }

    fn delete_script_pubkey_by_path(&self, keychain: String, child: u32) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM script_pubkeys WHERE keychain=$1 AND child=$2")?;
        self.client
            .borrow_mut()
            .execute(&statement, &[&keychain, &(child as i32)])?;

        Ok(())
    }

    fn delete_script_pubkey_by_script(&self, script: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM script_pubkeys WHERE script=$1")?;
        self.client.borrow_mut().execute(&statement, &[&script])?;

        Ok(())
    }

    fn delete_utxo_by_outpoint(&self, txid: &[u8], vout: u32) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM utxos WHERE txid=$1 AND vout=$2")?;
        self.client
            .borrow_mut()
            .execute(&statement, &[&txid, &(vout as i32)])?;

        Ok(())
    }

    fn delete_transaction_by_txid(&self, txid: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM transactions WHERE txid=$1")?;
        self.client.borrow_mut().execute(&statement, &[&txid])?;
        Ok(())
    }

    fn delete_transaction_details_by_txid(&self, txid: &[u8]) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM transaction_details WHERE txid=$1")?;
        self.client.borrow_mut().execute(&statement, &[&txid])?;
        Ok(())
    }

    fn delete_last_derivation_index_by_keychain(&self, keychain: String) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM last_derivation_indices WHERE keychain=$1")?;
        self.client.borrow_mut().execute(&statement, &[&keychain])?;

        Ok(())
    }

    fn delete_sync_time(&self) -> Result<(), Error> {
        let statement = self
            .client
            .borrow_mut()
            .prepare("DELETE FROM sync_time WHERE id = 0")?;
        self.client.borrow_mut().execute(&statement, &[])?;
        Ok(())
    }
}

impl BatchOperations for PostgresDatabase {
    fn set_script_pubkey(
        &mut self,
        script: &Script,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<(), Error> {
        let keychain = serde_json::to_string(&keychain)?;
        self.insert_script_pubkey(keychain, child, script.as_bytes())?;
        Ok(())
    }

    fn set_utxo(&mut self, utxo: &LocalUtxo) -> Result<(), Error> {
        self.insert_utxo(
            utxo.txout.value,
            serde_json::to_string(&utxo.keychain)?,
            utxo.outpoint.vout,
            &utxo.outpoint.txid,
            utxo.txout.script_pubkey.as_bytes(),
            utxo.is_spent,
        )?;
        Ok(())
    }

    fn set_raw_tx(&mut self, transaction: &Transaction) -> Result<(), Error> {
        match self.select_transaction_by_txid(&transaction.txid())? {
            Some(_) => {
                self.update_transaction(&transaction.txid(), &serialize(transaction))?;
            }
            None => {
                self.insert_transaction(&transaction.txid(), &serialize(transaction))?;
            }
        }
        Ok(())
    }

    fn set_tx(&mut self, transaction: &TransactionDetails) -> Result<(), Error> {
        match self.select_transaction_details_by_txid(&transaction.txid)? {
            Some(_) => {
                self.update_transaction_details(transaction)?;
            }
            None => {
                self.insert_transaction_details(transaction)?;
            }
        }

        if let Some(tx) = &transaction.transaction {
            self.set_raw_tx(tx)?;
        }

        Ok(())
    }

    fn set_last_index(&mut self, keychain: KeychainKind, value: u32) -> Result<(), Error> {
        self.update_last_derivation_index(serde_json::to_string(&keychain)?, value)?;
        Ok(())
    }

    fn set_sync_time(&mut self, ct: SyncTime) -> Result<(), Error> {
        self.update_sync_time(ct)?;
        Ok(())
    }

    fn del_script_pubkey_from_path(
        &mut self,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<Option<Script>, Error> {
        let keychain = serde_json::to_string(&keychain)?;
        let script = self.select_script_pubkey_by_path(keychain.clone(), child)?;
        match script {
            Some(script) => {
                self.delete_script_pubkey_by_path(keychain, child)?;
                Ok(Some(script))
            }
            None => Ok(None),
        }
    }

    fn del_path_from_script_pubkey(
        &mut self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, Error> {
        match self.select_script_pubkey_by_script(script.as_bytes())? {
            Some((keychain, child)) => {
                self.delete_script_pubkey_by_script(script.as_bytes())?;
                Ok(Some((keychain, child)))
            }
            None => Ok(None),
        }
    }

    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, Error> {
        match self.select_utxo_by_outpoint(&outpoint.txid, outpoint.vout)? {
            Some(local_utxo) => {
                self.delete_utxo_by_outpoint(&outpoint.txid, outpoint.vout)?;
                Ok(Some(local_utxo))
            }
            None => Ok(None),
        }
    }

    fn del_raw_tx(&mut self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        match self.select_transaction_by_txid(txid)? {
            Some(tx) => {
                self.delete_transaction_by_txid(txid)?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn del_tx(
        &mut self,
        txid: &Txid,
        include_raw: bool,
    ) -> Result<Option<TransactionDetails>, Error> {
        match self.select_transaction_details_by_txid(txid)? {
            Some(mut transaction_details) => {
                self.delete_transaction_details_by_txid(txid)?;

                if include_raw {
                    self.delete_transaction_by_txid(txid)?;
                } else {
                    transaction_details.transaction = None;
                }
                Ok(Some(transaction_details))
            }
            None => Ok(None),
        }
    }

    fn del_last_index(&mut self, keychain: KeychainKind) -> Result<Option<u32>, Error> {
        let keychain = serde_json::to_string(&keychain)?;
        match self.select_last_derivation_index_by_keychain(keychain.clone())? {
            Some(value) => {
                self.delete_last_derivation_index_by_keychain(keychain)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn del_sync_time(&mut self) -> Result<Option<SyncTime>, Error> {
        match self.select_sync_time()? {
            Some(value) => {
                self.delete_sync_time()?;

                Ok(Some(value))
            }
            None => Ok(None),
        }
    }
}

impl Database for PostgresDatabase {
    fn check_descriptor_checksum<B: AsRef<[u8]>>(
        &mut self,
        keychain: KeychainKind,
        bytes: B,
    ) -> Result<(), Error> {
        let keychain = serde_json::to_string(&keychain)?;

        match self.select_checksum_by_keychain(keychain.clone())? {
            Some(checksum) => {
                if checksum == bytes.as_ref().to_vec() {
                    Ok(())
                } else {
                    log::error!(
                        "checksum mismatch DB[{:?}], OTHER[{:?}]",
                        checksum,
                        bytes.as_ref().to_vec(),
                    );
                    Err(Error::ChecksumMismatch)
                }
            }
            None => {
                self.insert_checksum(keychain, bytes.as_ref())?;
                Ok(())
            }
        }
    }

    fn iter_script_pubkeys(&self, keychain: Option<KeychainKind>) -> Result<Vec<Script>, Error> {
        match keychain {
            Some(keychain) => {
                let keychain = serde_json::to_string(&keychain)?;
                self.select_script_pubkeys_by_keychain(keychain)
            }
            None => self.select_script_pubkeys(),
        }
    }

    fn iter_utxos(&self) -> Result<Vec<LocalUtxo>, Error> {
        self.select_utxos()
    }

    fn iter_raw_txs(&self) -> Result<Vec<Transaction>, Error> {
        self.select_transactions()
    }

    fn iter_txs(&self, include_raw: bool) -> Result<Vec<TransactionDetails>, Error> {
        match include_raw {
            true => self.select_transaction_details_with_raw(),
            false => self.select_transaction_details(),
        }
    }

    fn get_script_pubkey_from_path(
        &self,
        keychain: KeychainKind,
        child: u32,
    ) -> Result<Option<Script>, Error> {
        let keychain = serde_json::to_string(&keychain)?;
        match self.select_script_pubkey_by_path(keychain, child)? {
            Some(script) => Ok(Some(script)),
            None => Ok(None),
        }
    }

    fn get_path_from_script_pubkey(
        &self,
        script: &Script,
    ) -> Result<Option<(KeychainKind, u32)>, Error> {
        match self.select_script_pubkey_by_script(script.as_bytes())? {
            Some((keychain, child)) => Ok(Some((keychain, child))),
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<LocalUtxo>, Error> {
        self.select_utxo_by_outpoint(&outpoint.txid, outpoint.vout)
    }

    fn get_raw_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        match self.select_transaction_by_txid(txid)? {
            Some(tx) => Ok(Some(tx)),
            None => Ok(None),
        }
    }

    fn get_tx(&self, txid: &Txid, include_raw: bool) -> Result<Option<TransactionDetails>, Error> {
        match self.select_transaction_details_by_txid(txid)? {
            Some(mut transaction_details) => {
                if !include_raw {
                    transaction_details.transaction = None;
                }
                Ok(Some(transaction_details))
            }
            None => Ok(None),
        }
    }

    fn get_last_index(&self, keychain: KeychainKind) -> Result<Option<u32>, Error> {
        let keychain = serde_json::to_string(&keychain)?;
        let value = self.select_last_derivation_index_by_keychain(keychain)?;
        Ok(value)
    }

    fn get_sync_time(&self) -> Result<Option<SyncTime>, Error> {
        self.select_sync_time()
    }

    fn increment_last_index(&mut self, keychain: KeychainKind) -> Result<u32, Error> {
        let keychain_string = serde_json::to_string(&keychain)?;
        match self.get_last_index(keychain)? {
            Some(value) => {
                self.update_last_derivation_index(keychain_string, value + 1)?;
                Ok(value + 1)
            }
            None => {
                self.insert_last_derivation_index(keychain_string, 0)?;
                Ok(0)
            }
        }
    }
}

impl BatchDatabase for PostgresDatabase {
    type Batch = PostgresDatabase;

    fn begin_batch(&self) -> Self::Batch {
        let db = PostgresDatabase::new(&self.uri, &self.database, &self.descriptor, self.tls_mode)
            .expect("Unexpected failure");
        db.client
            .borrow_mut()
            .execute("BEGIN TRANSACTION;", &[])
            .unwrap();
        db
    }

    fn commit_batch(&mut self, batch: Self::Batch) -> Result<(), Error> {
        batch.client.borrow_mut().execute("END TRANSACTION;", &[])?;
        Ok(())
    }
}

pub fn get_schema_version(conn: &mut Client) -> PostgresResult<i32> {
    let statement = conn.prepare("SELECT version FROM version");
    match statement {
        Err(e) => match e.code() {
            Some(state) if state == &postgres::error::SqlState::UNDEFINED_TABLE => Ok(0),
            _ => Err(e),
        },
        Ok(stmt) => {
            let rows = conn.query(&stmt, &[])?;
            match rows.first() {
                Some(row) => {
                    let version: i32 = row.get(0);
                    Ok(version)
                }
                None => Ok(0),
            }
        }
    }
}

pub fn migrate(conn: &mut Client) -> Result<(), Error> {
    let version = get_schema_version(conn)?;
    let stmts = &MIGRATIONS[(version as usize)..];

    // begin transaction, all migration statements and new schema version commit or rollback
    let mut tx = conn.transaction()?;

    // execute every statement and return `Some` new schema version
    // if execution fails, return `Error`
    // if no statements executed returns `None`
    let new_version = stmts
        .iter()
        .enumerate()
        .map(|version_stmt| {
            log::info!(
                "executing db migration {}: `{}`",
                version + version_stmt.0 as i32 + 1,
                version_stmt.1
            );
            tx.execute(&version_stmt.1.to_string(), &[])
                // map result value to next migration version
                .map(|_| version_stmt.0 as i32 + version + 1)
        })
        .last()
        .transpose()?;
    // if `Some` new statement version, set new schema version
    if let Some(version) = new_version {
        tx.execute("UPDATE version SET version=$1", &[&version])?;
    } else {
        log::info!("db up to date, no migration needed");
    }

    // commit transaction
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
pub mod test {

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn get_database() -> Result<PostgresDatabase, Error> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Ok(PostgresDatabase::new(
            "postgresql://postgres@localhost",
            "test",
            &time.as_nanos().to_string(),
            true,
        )?)
    }

    #[test]
    fn test_script_pubkey() {
        crate::database::test::test_script_pubkey(get_database().unwrap());
    }

    #[test]
    fn test_batch_script_pubkey() {
        crate::database::test::test_batch_script_pubkey(get_database().unwrap());
    }

    #[test]
    fn test_iter_script_pubkey() {
        crate::database::test::test_iter_script_pubkey(get_database().unwrap());
    }

    #[test]
    fn test_del_script_pubkey() {
        crate::database::test::test_del_script_pubkey(get_database().unwrap());
    }

    #[test]
    fn test_utxo() {
        crate::database::test::test_utxo(get_database().unwrap());
    }

    #[test]
    fn test_raw_tx() {
        crate::database::test::test_raw_tx(get_database().unwrap());
    }

    #[test]
    fn test_tx() {
        crate::database::test::test_tx(get_database().unwrap());
    }

    #[test]
    fn test_last_index() {
        crate::database::test::test_last_index(get_database().unwrap());
    }

    #[test]
    fn test_sync_time() {
        crate::database::test::test_sync_time(get_database().unwrap());
    }

    #[test]
    fn test_txs() {
        crate::database::test::test_list_transaction(get_database().unwrap());
    }

    #[test]
    fn test_iter_raw_txs() {
        crate::database::test::test_iter_raw_txs(get_database().unwrap());
    }

    #[test]
    fn test_del_path_from_script_pubkey() {
        crate::database::test::test_del_path_from_script_pubkey(get_database().unwrap());
    }

    #[test]
    fn test_iter_script_pubkeys() {
        crate::database::test::test_iter_script_pubkeys(get_database().unwrap());
    }

    #[test]
    fn test_del_utxo() {
        crate::database::test::test_del_utxo(get_database().unwrap());
    }

    #[test]
    fn test_del_raw_tx() {
        crate::database::test::test_del_raw_tx(get_database().unwrap());
    }

    #[test]
    fn test_del_tx() {
        crate::database::test::test_del_tx(get_database().unwrap());
    }

    #[test]
    fn test_del_last_index() {
        crate::database::test::test_del_last_index(get_database().unwrap());
    }

    #[test]
    fn test_check_descriptor_checksum() {
        crate::database::test::test_check_descriptor_checksum(get_database().unwrap());
    }

    // Issue 801: https://github.com/bitcoindevkit/bdk/issues/801
    #[test]
    fn test_unique_spks() {
        use crate::bitcoin::hashes::hex::FromHex;
        use crate::database::*;

        let mut db = get_database().unwrap();

        let script = Script::from(
            Vec::<u8>::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac").unwrap(),
        );
        let path = 42;
        let keychain = KeychainKind::External;

        for _ in 0..100 {
            db.set_script_pubkey(&script, keychain, path).unwrap();
        }

        let statement = db
            .client
            .borrow_mut()
            .prepare(
                "select keychain,child,count(child) from script_pubkeys group by keychain,child;",
            )
            .unwrap();
        let rows = db.client.borrow_mut().query(&statement, &[]).unwrap();
        for row in rows {
            let keychain: String = row.get(0);
            let child: i32 = row.get(1);
            let count: i64 = row.get(2);

            assert_eq!(
                count, 1,
                "keychain={}, child={}, count={}",
                keychain, child, count
            );
        }
    }
}
