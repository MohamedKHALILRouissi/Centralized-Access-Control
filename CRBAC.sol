/ @authors:   mohamed khalil rouissi    mohamed amine ghodhbene 
// @description: centralized role based access control 
/*
inherit for code reuse save time 
*/



pragma solidity ^0.8.0;

import "./ICentralizedRoleBasedAccess.sol";


abstract contract CRBACparent {

    address internal CRBAC;

    modifier onlyAdmin(){ 
       require(ICentralizedRoleBasedAccess(CRBAC).CheckAdmins(msg.sender) == true,"the user must be admin") ;
       _;
    }
    modifier onlyRole(string memory _Role) {
        require(ICentralizedRoleBasedAccess(CRBAC).CheckAssignedRole(msg.sender,_Role) == true,"Role is required for this action");
        _;
    }
}
