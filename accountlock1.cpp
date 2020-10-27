#include "accountlock1.hpp"


void accountlock1::lock(name target_contract, const time_point_sec &lock_time, string public_key_str) {
require_auth(target_contract);


//Time format example: "2020-10-24T16:46:07"
//time_point_sec unlock_time = current_time_point().sec_since_epoch() + lock_time;
time_point_sec unlock_time = lock_time;


			// CHECK PULIC KEY ---------------------------------------------------------------------------------
			check(public_key_str.length() == 53, "Length of public key should be 53");
    
            string pubkey_prefix("EOS");
            auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
            check(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");
            auto base58substr = public_key_str.substr(pubkey_prefix.length());
    
            vector<unsigned char> vch;
            check(decode_base58(base58substr, vch), "Decode pubkey failed");
            check(vch.size() == 37, "Invalid public key");
    
 
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
      check(myindex.unlock_time != eosio::time_point_sec(0) && myindex.unlock_time <  eosio::time_point_sec(current_time_point()), "lock time not expired");

            string public_key_str = myindex.public_key_str;
            check(public_key_str.length() == 53, "Length of public key should be 53");

            string pubkey_prefix("EOS");
            auto result = mismatch(pubkey_prefix.begin(), pubkey_prefix.end(), public_key_str.begin());
            check(result.first == pubkey_prefix.end(), "Public key should be prefix with EOS");
            auto base58substr = public_key_str.substr(pubkey_prefix.length());

            vector<unsigned char> vch;
            check(decode_base58(base58substr, vch), "Decode pubkey failed");
            check(vch.size() == 37, "Invalid public key");

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



void accountlock1::ontransfer(name from, name to, asset quantity, string memo) {
    
    if(from !=_self && to == _self){
            
          check(to != _self,"please do not send any token to this account");

     }
   
}
