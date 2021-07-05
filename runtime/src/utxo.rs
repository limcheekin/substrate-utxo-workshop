use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
	decl_event, decl_module, decl_storage,
	dispatch::{DispatchResult, Vec},
	ensure,
};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};
use sp_core::{H256, H512};
use sp_runtime::traits::{BlakeTwo256, Hash, SaturatedConversion};
use sp_runtime::transaction_validity::{TransactionLongevity, ValidTransaction};
use sp_std::collections::btree_map::BTreeMap;

pub trait Trait: system::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionInput {
	pub outpoint: H256,  // reference to UTXO to be spent
	pub sigscript: H512, // proof
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionOutput {
	pub value: Value, // value associated with this UTXO
	pub pubkey: H256, // public key associated with this output, key of the UTXO's owner
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct Transaction {
	pub inputs: Vec<TransactionInput>,
	pub outputs: Vec<TransactionOutput>,
}

decl_storage! {
	trait Store for Module<T: Trait> as Utxo {
		UtxoStore build(|config: &GenesisConfig| {
			config.genesis_utxos
				.iter()
				.cloned()
				.map(|u| (BlakeTwo256::hash_of(&u, u)))
				.collect::<Vec<_>>()
		}) : map hasher(identity) H256 => Option<TransactionOutput>;

		pub RewardTotal get(reward_total): Value;
	}

	init_genesis {
		config(genesis_utxos): Vec<TransactionOutput>;
	}
}

// External functions: callable by the end user
decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		pub fn get_simple_transaction(transaction: &Transaction) -> Vec<u8> {
			let mut trx = transaction.cloned();

			for input in trx.inputs.iter_mut() {
				input.sigscript = H512::zero(); // 0x000...
			}

			trx.encode();
		}

		/// Check transaction for validity, errors, & race conditions
		/// Called by both transaction pool and runtime execution
		///
		/// Ensures that:
		/// - inputs and outputs are not empty
		/// - all inputs match to existing, unspent and unlocked outputs
		/// - each input is used exactly once
		/// - each output is defined exactly once and has nonzero value
		/// - total output value must not exceed total input value
		/// - new outputs do not collide with existing ones
		/// - sum of input and output values does not overflow
		/// - provided signatures are valid
		/// - transaction outputs cannot be modified by malicious nodes		
		pub fn validate_transaction(transaction: &Transaction) -> Result<Value, &'static str> {
			// validate inputs and outputs
			ensure!(!transaction.inputs.is_empty(), "no inputs");
			ensure!(!transaction.outputs.is_empty(), "no outputs");

			// make sure each input and each output is used exactly once
			{
				let input_set: BTreeMap<_, ()> = transaction.inputs.iter()
												 .map(|input| (input, ())).collect();
				ensure!(input_set.len() == transaction.inputs.len(), "each input must only be used once");												 
			}

			{
				let output_set: BTreeMap<_, ()> = transaction.outputs.iter()
												 .map(|output| (output, ())).collect();
				ensure!(output_set.len() == transaction.outputs.len(), "each output must only be used once");												 
			}

			let simple_transaction = Self::get_simple_transaction(&transaction);
			let mut total_input: Value = 0;
			let mut total_output: Value = 0;

			for input in transaction.inputs.iter() {
				if let Some(input_utxo) = UtxoStore::get(&input.outpoint) {
					// validate signature
					ensure!(sp_io::crypto::sr25519_verify(
						&Signature::from_raw(*input.sigscript.as_fixed_bytes()),
						&simple_transaction,
						&Public.from_h256(input_utxo.pubkey)
					), "Signature must be valid");

					total_input = total_input.checked_add(input_utxo.value).ok_or("input value overflow")?;
				} else {
					// TODO
				}
			}

			let mut output_index: u64 = 0;

			for output in transaction.outputs.iter() {
				ensure!(output.value > 0, "output value must be non-zero");
				let hash = BlakeTwo256::hash_of(&(&transaction.encode(), output_index));
				output_index = output_index.checked_add(1).ok_or("output index overflow")?;
				ensure!(!UtxoStore::contains_key(hash), "output already exists");
				total_output = total_output.checked_add(output_utxo.value).ok_or("output value overflow")?;
			}

			ensure!(total_input >= total_output, "total input must not exceed total output");

			let reward = total_input.checked_sub(total_output).ok_or("reward underflow")?;
			
			Ok(reward)
		}

		pub fn spend(_origin, transaction: Transaction) -> DispatchResult {
			// TODO check that trxn is valid
			let reward: Self::validate_transaction(&transaction)?;
			// write to storage
			Self::update_storage(&transaction, reward)?;

			// emit success event
			Self::deposit_event(Event::TransactionSuccess(transaction));
			Ok(())
		}

		fn on_finalize() {
			let auth: Vec<_> = Aura::authorities.iter().map(|x|{
				let r: &Public = x.as_ref();
				r.0.into()		
			}).collect();
			Self::disperse_reward(&auth);
		}

	}
}

decl_event! {
	pub enum Event {
		TransactionSuccess(Transaction),
	}
}

impl<T: Trait> Module<T> {
	fn update_storage(transaction: &Transaction, reward: Value) -> DispatchResult {
		let new_total = <RewardTotal>::get()
			.checked_add(1)
			.ok_or("reward overflow")?;
		RewardTotal::put(new_total);
		// remove UTXO input from the UTXO store
		for input in &transaction.inputs {
			<UtxoStore>::remove(input.outpoint);
		}

		// create the new UTXOs in UTXO store
		let mut index: u64 = 0;
		for output in &transaction.outputs {
			let hash = BlakeTwo256::hash_of(&(&transaction.encode(), index));
			index = index.checked_add(1).ok_or("output index overflow")?;
			<UtxoStore>::insert(hash, output);
		}

		Ok(())
	}

	fn disperse_reward(authorities:&[H256]) {
		// divide the reward fairly
		let reward = RewardTotal::take();
		let share_value: Value = reward
		.checked_div(authorities.len() as Value)
		.ok_or("No authorities")?;
		
		if share_value == 0 { return }

		let remainder = reward
		.checked_sub(authorities.len() as Value)
		.ok_or("Sub underflow")?;

		RewardTotal::put(remainder as Value);

		// create UTXO per validator and store it
		for authority in authorities {
			let utxo = TransactionOutput(
				value: share_value,
				pubkey: *authority,
			);

			let hash = BlakeTwo256::hash_of( &(&utxo, 
			system::Module<T>::block_number().saturated_into()::<u64>()));

			if !UtxoStore.contains_key(hash) {
				UtxoStore::insert(hash, utxo);
				sp_runtime::print("Transaction reward sent to");
				sp_runtime::print(hash.as_fixed_bytes() as &[u8]);
			} else {
				sp_runtime::print("Transaction reward wasted due to has collision!");
			}
		}
	}
}

/// Tests for this module
#[cfg(test)]
mod tests {
	use super::*;

	use frame_support::{
		assert_err, assert_ok, impl_outer_origin, parameter_types, weights::Weight,
	};
	use sp_core::testing::{KeyStore, SR25519};
	use sp_core::traits::KeystoreExt;
	use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	parameter_types! {
			pub const BlockHashCount: u64 = 250;
			pub const MaximumBlockWeight: Weight = 1024;
			pub const MaximumBlockLength: u32 = 2 * 1024;
			pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
	}
	impl system::Trait for Test {
		type Origin = Origin;
		type Call = ();
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type Event = ();
		type BlockHashCount = BlockHashCount;
		type MaximumBlockWeight = MaximumBlockWeight;
		type MaximumBlockLength = MaximumBlockLength;
		type AvailableBlockRatio = AvailableBlockRatio;
		type Version = ();
		type ModuleToIndex = ();
		type AccountData = ();
		type OnNewAccount = ();
		type OnKilledAccount = ();
	}
	impl Trait for Test {
		type Event = ();
	}

	type Utxo = Module<Test>;

	// need to manually import this crate since its no include by default	
	use hex_literal::hex;

	const ALICE_PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
	const GENESIS_UTXO: [u8; 32] = hex!("79eabcbd5ef6e958c6a7851b36da07691c19bda1835a08f875aa286911800999");


	fn new_test_ext() -> sp_io::TestExternalities {
		// create key for a test user: Alice
		let keystore = Keystore::new();
		let alice_pub_key = keystore.write().sr25519_generate_new(SR25519, Some(ALICE_PHRASE))?;
	
		let mut t = system::GenesisConfig::default()
					.build_storage::<Test>()?;
		t.top.extend(
			GenesisConfig {
				genesis_utxos: vec![
					TransactionOutput {
						value: 100,
						pubkey: H256::from(alice_pub_key),
					}
				],
				..Default.default()
			}
			.build_storage()?
			.top,
		); 

		let mut ext = sp_io::TestExternalities::from(t);
		// store alice's keys storage
		ext.register_extension(KeystoreExt(keystore));

		ext
	}

	#[test]
	fn test_simple_transaction() {
		new_test_ext().execute_with(|| {
			let alice_pub_key = sp_io::crypto::sr25519_public_keys(SR25519)[0];	
			// Alice wants to send herself a new utxo of value 50.
			let mut transaction = Transaction {
				inputs: vec![TransactionInput {
					outpoint: H256::from(GENESIS_UTXO),
					sigscript: H512::zero(),
				}],
				outputs: vec![TransactionOutput {
					value: 50,
					pubkey: H256::from(alice_pub_key),
				}],
			};

			let alice_signature = sp_io::crypto::sr25519_sign(SR25519, &alice_pub_key, &transaction.encode())?;

			transaction.inputs[0].sigscript = H512::from(alice_signature);
			let new_utxo_hash = BlakeTwo256::hash_of(&(&transaction.encode(), 0 as u64));

			assert_ok!(Utxo::spend(Origin::signed(0), transaction));
			assert!(!UtxoStore::contains_key(H256::from(GENESIS_UTXO)));
			assert!(UtxoStore::contains_key(new_utxo_hash));
			assert_eq!(50, UtxoStore::get(new_utxo_hash)?.value);
		});

	}
}
