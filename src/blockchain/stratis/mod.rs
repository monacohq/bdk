use std::collections::HashSet;

use bitcoin::consensus::{deserialize, deserialize_partial, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHeader, Script, Transaction, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ureq::Agent;

use crate::blockchain::utils::{ElectrumLikeSync, ElsGetHistoryRes};
use crate::blockchain::{Blockchain, Capability, ConfigurableBlockchain, Progress};
use crate::database::BatchDatabase;
use crate::{Error, FeeRate};

#[derive(Debug)]
pub struct StratisBlockchain {
    /// Rpc client to the node, includes the wallet name
    rpc_client: Client,
    node_url: String,
    agent: Agent,
}

#[derive(Debug, Clone)]
pub struct StratisConfig {
    pub rpc_url: String,
    pub node_url: String,
    pub agent: Agent,
}

impl Blockchain for StratisBlockchain {
    fn get_capabilities(&self) -> HashSet<Capability> {
        [
            Capability::FullHistory,
            // Capability::AccurateFees,
            Capability::GetAnyTx,
        ]
        .into()
    }

    fn setup<D: BatchDatabase, P: 'static + Progress>(
        &self,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        // self.electrum_like_setup(20, database, progress_update)
        Ok(())
    }

    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<Transaction>, Error> {
        let res = self
            .rpc_client
            .call::<String>("getrawtransaction", &[Value::String(txid.to_hex())])
            .map_err(|e| Error::Rpc(e))?;
        let bytes = Vec::<u8>::from_hex(&res)?;
        let tx = deserialize(&bytes)?;
        Ok(Some(tx))
    }

    fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        let res = self.rpc_client.call::<Value>(
            "sendrawtransaction",
            &[Value::String(serialize(tx).to_hex())],
        );

        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::Rpc(e)),
        }
    }

    fn get_height(&self) -> Result<u32, Error> {
        let res = self.rpc_client.call::<u32>("getblockcount", &[]);

        match res {
            Ok(height) => Ok(height),
            Err(e) => Err(Error::Rpc(e)),
        }
    }

    fn estimate_fee(&self, target: usize) -> Result<FeeRate, Error> {
        Ok(FeeRate::from_sat_per_vb(100000.))
    }
}

impl ElectrumLikeSync for StratisBlockchain {
    fn els_batch_script_get_history<'s, I: IntoIterator<Item = &'s Script> + Clone>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ElsGetHistoryRes>>, Error> {
        todo!()
    }

    fn els_batch_transaction_get<'s, I: IntoIterator<Item = &'s Txid> + Clone>(
        &self,
        txids: I,
    ) -> Result<Vec<Transaction>, Error> {
        todo!()
    }

    fn els_batch_block_header<I: IntoIterator<Item = u32> + Clone>(
        &self,
        heights: I,
    ) -> Result<Vec<BlockHeader>, Error> {
        todo!()
    }
}

impl ConfigurableBlockchain for StratisBlockchain {
    type Config = StratisConfig;

    fn from_config(config: &Self::Config) -> Result<Self, Error> {
        let rpc_client = Client::new_ureq(&config.rpc_url, config.agent.clone());
        Ok(Self {
            rpc_client,
            node_url: config.node_url.to_string(),
            agent: config.agent.clone(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodeRawTx {
    raw_hex: String,
}

fn script_to_scripthash(script: &Script) -> String {
    sha256::Hash::hash(script.as_bytes()).into_inner().to_hex()
}
