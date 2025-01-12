use crate::{transaction::RlpEcdsaTx, SignableTransaction, Signed, Transaction, TxType, Typed2718};
use alloy_eips::{eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Bytes, ChainId, PrimitiveSignature as Signature, TxKind, B256, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
use core::mem;

/// A Sponsored transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[doc(alias = "SponsoredTransaction", alias = "TransactionSponsored", alias = "SponsoredTx")]
pub struct TxSponsored {
    /// EIP-155: Simple replay attack protection
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub nonce: u64,
    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_priority_fee_per_gas: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_fee_per_gas: u128,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    #[cfg_attr(
        feature = "serde",
        serde(with = "alloy_serde::quantity", rename = "gas", alias = "gasLimit")
    )]
    pub gas_limit: u64,
    /// The 160-bit address of the message call’s recipient or, for a contract creation
    /// transaction, ∅, used here to denote the only member of B0 ; formally Tt.
    #[cfg_attr(feature = "serde", serde(default))]
    pub to: TxKind,
    /// A scalar value equal to the number of Wei to
    /// be transferred to the message call’s recipient or,
    /// in the case of contract creation, as an endowment
    /// to the newly created account; formally Tv.
    pub value: U256,
    /// Sponsored transaction fields.
    pub expired_time: u64,
    pub payer_v: U256,
    pub payer_r: U256,
    pub payer_s: U256,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
}

impl TxSponsored {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub(crate) const fn tx_type() -> TxType {
        TxType::Sponsored
    }

    /// Calculates a heuristic for the in-memory size of the [TxSponsored]
    /// transaction.
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ChainId>() + // chain_id
        mem::size_of::<u64>() + // nonce
        mem::size_of::<u64>() + // gas_limit
        mem::size_of::<u128>() + // max_fee_per_gas
        mem::size_of::<u128>() + // max_priority_fee_per_gas
        self.to.size() + // to
        mem::size_of::<U256>() + // value
        mem::size_of::<u64>() + // expired_time
        mem::size_of::<U256>() + // payer_v
        mem::size_of::<U256>() + // payer_r
        mem::size_of::<U256>() + // payer_s
        self.input.len() // input
    }
}

impl RlpEcdsaTx for TxSponsored {
    const DEFAULT_TX_TYPE: u8 = { Self::tx_type() as u8 };

    /// Outputs the length of the transaction's fields, without a RLP header.
    fn rlp_encoded_fields_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.0.length()
            + self.expired_time.length()
            + self.payer_v.length()
            + self.payer_r.length()
            + self.payer_s.length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without
    /// a RLP header.
    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.expired_time.encode(out);
        self.payer_v.encode(out);
        self.payer_r.encode(out);
        self.payer_s.encode(out);
    }

    /// Decodes the inner [TxSponsored] fields from RLP bytes.
    ///
    /// NOTE: This assumes a RLP header has already been decoded, and _just_
    /// decodes the following RLP fields in the following order:
    ///
    /// - `chain_id`
    /// - `nonce`
    /// - `max_priority_fee_per_gas`
    /// - `max_fee_per_gas`
    /// - `gas_limit`
    /// - `to`
    /// - `value`
    /// - `data` (`input`)
    /// - `expired_time`
    /// - `payer_v`
    /// - `payer_r`
    /// - `payer_s`
    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            expired_time: Decodable::decode(buf)?,
            payer_v: Decodable::decode(buf)?,
            payer_r: Decodable::decode(buf)?,
            payer_s: Decodable::decode(buf)?,
        })
    }
}

impl Transaction for TxSponsored {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.nonce
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        base_fee.map_or(self.max_fee_per_gas, |base_fee| {
            // if the tip is greater than the max priority fee per gas, set it to the max
            // priority fee per gas + base fee
            let tip = self.max_fee_per_gas.saturating_sub(base_fee as u128);
            if tip > self.max_priority_fee_per_gas {
                self.max_priority_fee_per_gas + base_fee as u128
            } else {
                // otherwise return the max fee per gas
                self.max_fee_per_gas
            }
        })
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn kind(&self) -> TxKind {
        self.to
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    #[inline]
    fn value(&self) -> U256 {
        self.value
    }

    #[inline]
    fn input(&self) -> &Bytes {
        &self.input
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        None
    }

    #[inline]
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    #[inline]
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl Typed2718 for TxSponsored {
    fn ty(&self) -> u8 {
        TxType::Sponsored as u8
    }
}

impl SignableTransaction<Signature> for TxSponsored {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(Self::tx_type() as u8);
        self.encode(out)
    }

    fn payload_len_for_signature(&self) -> usize {
        self.length() + 1
    }

    fn into_signed(self, signature: Signature) -> Signed<Self> {
        let tx_hash = self.tx_hash(&signature);
        Signed::new_unchecked(self, signature, tx_hash)
    }
}

impl Encodable for TxSponsored {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxSponsored {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

/// Bincode-compatible [`TxSponsored`] serde implementation.
#[cfg(all(feature = "serde", feature = "serde-bincode-compat"))]
pub(super) mod serde_bincode_compat {
    use alloc::borrow::Cow;
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Bytes, ChainId, TxKind, U256};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    /// Bincode-compatible [`super::TxSponsored`] serde implementation.
    ///
    /// Intended to use with the [`serde_with::serde_as`] macro in the following way:
    /// ```rust
    /// use alloy_consensus::{serde_bincode_compat, TxSponsored};
    /// use serde::{Deserialize, Serialize};
    /// use serde_with::serde_as;
    ///
    /// #[serde_as]
    /// #[derive(Serialize, Deserialize)]
    /// struct Data {
    ///     #[serde_as(as = "serde_bincode_compat::transaction::TxSponsored")]
    ///     transaction: TxSponsored,
    /// }
    /// ```
    #[derive(Debug, Serialize, Deserialize)]
    pub struct TxSponsored<'a> {
        chain_id: ChainId,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        #[serde(default)]
        to: TxKind,
        value: U256,
        expired_time: u64,
        payer_v: U256,
        payer_r: U256,
        payer_s: U256,
        input: Cow<'a, Bytes>,
    }

    impl<'a> From<&'a super::TxSponsored> for TxSponsored<'a> {
        fn from(value: &'a super::TxSponsored) -> Self {
            Self {
                chain_id: value.chain_id,
                nonce: value.nonce,
                gas_limit: value.gas_limit,
                max_fee_per_gas: value.max_fee_per_gas,
                max_priority_fee_per_gas: value.max_priority_fee_per_gas,
                to: value.to,
                value: value.value,
                expired_time: value.expired_time,
                payer_v: value.payer_v,
                payer_r: value.payer_r,
                payer_s: value.payer_s,
                input: Cow::Borrowed(&value.input),
            }
        }
    }

    impl<'a> From<TxSponsored<'a>> for super::TxSponsored {
        fn from(value: TxSponsored<'a>) -> Self {
            Self {
                chain_id: value.chain_id,
                nonce: value.nonce,
                gas_limit: value.gas_limit,
                max_fee_per_gas: value.max_fee_per_gas,
                max_priority_fee_per_gas: value.max_priority_fee_per_gas,
                to: value.to,
                value: value.value,
                expired_time: value.expired_time,
                payer_v: value.payer_v,
                payer_r: value.payer_r,
                payer_s: value.payer_s,
                input: value.input.into_owned(),
            }
        }
    }

    impl SerializeAs<super::TxSponsored> for TxSponsored<'_> {
        fn serialize_as<S>(source: &super::TxSponsored, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            TxSponsored::from(source).serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, super::TxSponsored> for TxSponsored<'de> {
        fn deserialize_as<D>(deserializer: D) -> Result<super::TxSponsored, D::Error>
        where
            D: Deserializer<'de>,
        {
            TxSponsored::deserialize(deserializer).map(Into::into)
        }
    }

    #[cfg(test)]
    mod tests {
        use arbitrary::Arbitrary;
        use rand::Rng;
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;

        use super::super::{serde_bincode_compat, TxSponsored};

        #[test]
        fn test_tx_eip1559_bincode_roundtrip() {
            #[serde_as]
            #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
            struct Data {
                #[serde_as(as = "serde_bincode_compat::TxSponsored")]
                transaction: TxSponsored,
            }

            let mut bytes = [0u8; 1024];
            rand::thread_rng().fill(bytes.as_mut_slice());
            let data = Data {
                transaction: TxSponsored::arbitrary(&mut arbitrary::Unstructured::new(&bytes))
                    .unwrap(),
            };

            let encoded = bincode::serialize(&data).unwrap();
            let decoded: Data = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded, data);
        }
    }
}
