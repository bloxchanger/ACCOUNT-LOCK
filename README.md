# ACCOUNT-LOCK
Temporary immutablity for EOSIO smart contracts
Locks your EOSIO account and ensures that your smart contract is immutable for a given time period

A completely secure dapp that can only restore the owner and active keys after a pre-defined time

Developed as a smart contract on the Eos mainnet

Ensures that no-one has control of a given account while locked




GETTING LOCKED

Follow these steps to provide temporary immutability to your account:

1. Add the accountlock1@eosio.code permission to the owner authority of your account:

cleos set account permission YOUR_CONTRACT owner ‘{“threshold”: 1,”keys”: [{“key”: “CURRENT_PUBLIC_KEY”,”weight”: 1}], “accounts”: [{“permission”:{“actor”:”accountlock1″,”permission”:”eosio.code”},”weight”:1}]}’ -p YOUR_CONTRACT@owner

2. Call the lock action of the accountlock1 smart contract. Set the following parameters:

target_contract: [YOUR_CONTRACT]
lock_time: [insert the lock time period in seconds]
public_key_string: [insert the public key that should be used to restore your account after the lock time has expired]
Warning: make sure to insert correctly your public key string or you might permanently loose control of your account.

3. After the lock time has expired, call the unlock action of the accountlock1 contract to restore the owner authority:

target_contract: [YOUR_CONTRACT]
This action will unlock your account by setting the public_key_string provided at the previous step as the new owner authority.

PROOF OF LOCK AND EXPIRY TIME

Locked account names and the corresponding lock-up expiry dates are recorded on a table on the accountlock1 contract. Any user of your dapp can check with a simple blockchain explorer that your account is currently locked and the date in which it will be unlocked.
