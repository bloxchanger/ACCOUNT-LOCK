#include "accountlock1.hpp"

void accountlock1::settarget(name mytarget) {

    auto state = _myConfig.find(0);
    if (state == _myConfig.end()) {
        _myConfig.emplace(_self,  [&](auto& newrow) {
            newrow.id = 0;
            newrow.receiver_account = mytarget;
        });
    }
    else {
        auto& itr = _myConfig.get(0);
        require_auth(itr.receiver_account);
        _myConfig.modify(itr, _self,  [&](auto& row) {
            row.receiver_account = mytarget;
        });
    }

}



void accountlock1::lock(name target_contract, uint64_t lock_time, string public_key_str) {
require_auth(target_contract);

eosio::time_point_sec unlock_time = eosio::time_point_sec(now() + lock_time);

			// CHECK PULIC KEY ---------------------------------------------------------------------------------
			eosio_assert(public_key_str.length() == 53, "Length of public key should be 53");
    
            string pubkey_prefix("EOS");
            auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
            eosio_assert(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");
            auto base58substr = public_key_str.substr(pubkey_prefix.length());
    
            vector<unsigned char> vch;
            eosio_assert(decode_base58(base58substr, vch), "Decode pubkey failed");
            eosio_assert(vch.size() == 37, "Invalid public key");
    
 
	//set corresponding item
    auto myid = _myItems.available_primary_key();

    //CREATE THE NEW ITEM
    _myItems.emplace(_self,  [&](auto& new_item) {   //target_contract,  [&](auto& new_item) {
        new_item.id = myid;
        new_item.locked_contract = target_contract;
        new_item.unlock_time = unlock_time;
	    new_item.public_key_str = public_key_str;  
    });


    // change owner's permission

            auto permlev = permission_level{"accountlock1"_n , "eosio.code"_n };

            permission_level_weight perm_weight = {
                .permission = permlev,
                .weight = 1,
            };
            authority myautho= authority{
                .threshold = 1,
                .keys = {},
                .accounts = {perm_weight},
                .waits = {}
            };


            action(
                    permission_level{ target_contract, "owner"_n },
                    "eosio"_n,
                    "updateauth"_n,
                    make_tuple(target_contract, "active"_n, "owner"_n, myautho)
            ).send();  // updateauth(account, permission, parent, new_auth)
			
			
			action(
                   permission_level{ target_contract, "owner"_n },
                    "eosio"_n,
                    "updateauth"_n,
                    make_tuple(target_contract, "owner"_n, ""_n, myautho)
            ).send();  // updateauth(account, permission, parent, new_auth)

}


void accountlock1::unlock(name target_contract) {

for(auto& myindex : _myItems) {
  if ( myindex.locked_contract == target_contract) {
      //if lock time has expired, restore owner's permission
      eosio_assert(myindex.unlock_time != eosio::time_point_sec(0) && myindex.unlock_time <  eosio::time_point_sec(now()), "lock time not expired");

            string public_key_str = myindex.public_key_str;
            eosio_assert(public_key_str.length() == 53, "Length of public key should be 53");

            string pubkey_prefix("EOS");
            auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
            eosio_assert(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");
            auto base58substr = public_key_str.substr(pubkey_prefix.length());

            vector<unsigned char> vch;
            eosio_assert(decode_base58(base58substr, vch), "Decode pubkey failed");
            eosio_assert(vch.size() == 37, "Invalid public key");

            array<unsigned char,33> pubkey_data;
            copy_n(vch.begin(), 33, pubkey_data.begin());

            checksum160 check_pubkey;
            check_pubkey = ripemd160(reinterpret_cast<char *>(pubkey_data.data()), 33);


      auto permlev = permission_level{ "accountlock1"_n, "eosio.code"_n };
      
      permission_level_weight perm_weight = {
          .permission = permlev,
          .weight = 1,
      };
      
			signup_public_key pubkey = {
                .type = 0,
                .data = pubkey_data,
            };
            key_weight pubkey_weight = {
                .key = pubkey,
                .weight = 1,
            };
      
            authority restoreactive = authority{
                  .threshold = 1,
                  .keys = {pubkey_weight},
                  .accounts = {},
                  .waits = {}
            };
      
            authority restoreowner = authority{
                    .threshold = 1,
                    .keys = {pubkey_weight},
                    .accounts = {perm_weight},
                    .waits = {}
            };


			action(
                    permission_level{ target_contract, "owner"_n },
                    "eosio"_n,
                    "updateauth"_n,
                    make_tuple(target_contract, "active"_n, "owner"_n, restoreactive)
             ).send();
			
			
			action(
                    permission_level{ target_contract, "owner"_n },
                    "eosio"_n,
                    "updateauth"_n,
                    make_tuple(target_contract, "owner"_n, ""_n, restoreowner)
            ).send();  // updateauth(account, permission, parent, new_auth)


        auto item_itr = _myItems.find(myindex.id);
        if (item_itr != _myItems.end()) {
          _myItems.erase(item_itr);
        }
        break;

  } 

}
}



void accountlock1::transfer(name from, name to, asset quantity, string memo) {
    auto& itr = _myConfig.get(0);
    
    if(from !=_self && to == _self){
            
          eosio_assert(quantity.symbol.is_valid(),"invalid quantity");
          eosio_assert(quantity.amount>0, "only positive quantity allowed");
          eosio_assert(quantity.symbol == EOS_SYMBOL, "only EOS tokens allowed");
          
          // send amount to the account specified in config.sendeverythingto---------------------------- 
          action(
            permission_level{_self, "active"_n},
            "eosio.token"_n, "transfer"_n,
            std::make_tuple(_self, itr.receiver_account, quantity, string("redirect from accountlock1"))
          ).send();
          //--------------------------------------------------------------------------------

     }
   
}



extern "C" void apply(uint64_t receiver, uint64_t code, uint64_t action)
{
  if (code=="eosio.token"_n.value && action =="transfer"_n.value) {
    eosio::execute_action(eosio::name(receiver), eosio::name(code), &accountlock1::transfer);
  }
  else {
    switch (action) 
    {
      EOSIO_DISPATCH_HELPER(accountlock1, (settarget)(lock)(unlock))
    }
  }

}


