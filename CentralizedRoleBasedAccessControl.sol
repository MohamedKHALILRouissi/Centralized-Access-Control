//SPDX-License-Identifier: opensource
// @authors:   mohamed khalil rouissi    mohamed amine ghodhbene 
// @description: centralized role based access control 
/*
 * rootadmin can be declared as any other Role but the root admin is the trust authority 
 * not address should live in the storage without role 
 * admins can't add admins or remove admins 
*/

/*
 * Description : 
 *  Centralized Role-Based Access Control (CRBAC) system. It allows defining and managing roles and permissions for users of a DApp, granting or revoking access
 *  based on those roles. The contract defines several events for logging various actions such as adding or removing a user or a role, revoking user roles,
 *  creating or revoking admin roles, removing or declaring roles, and removing a role forcibly.
 * 
*/
//QUOTE:  “Not every legend is a myth, some are flesh and blood. Some legends walk among us, but they aren’t born, they’re built. Legends are made from iron & sweat, mind and muscle, blood and vision and victory. Legends are champions, they grow, they win, they conquer. There’s a legend behind every legacy, there’s a blueprint behind every legend.”
/*
    Future work 
    https://www.youtube.com/watch?v=OwppworJGzs&ab_channel=EthereumFoundation , account abstraction 
*/


pragma solidity ^0.8.0;

import "./PausableLayer.sol";

contract CentralizedRoleBasedAccessControl is PausableLayer  {


    event RoleDeclared(uint256 timestamp, string _Role);
    event RoleRemoved(uint256 timestamp, string _Role);
    event AdminRevoked(uint256 timestamp, address _address);   
    event AdminCreated(uint256 timestamp, address _address);
    event ForceRoleRemoved(uint256 timestamp, string _Role);
    event UserRemoved(uint256 timestamp, address _address);
    event UserCreated(uint256 timestamp, address _address, string _Role);
    event UserRoleRevoked(uint256 timestamp, address _address, string _Role);
    event UserAddRole(uint256 timestamp, address _address, string _Role);

    struct role {
        bool check;
        uint number;
    }

    address internal RootAdmin;
    
    string[] public ListOfRoles;
    address[] addresses; 
    //bool public state = true;
    mapping(string => role) public Role;
    mapping(address => bool) internal Admins;
    mapping(address => string[]) internal Roles;  //@dev this will proctect the information from total data dumping

    constructor(){
        //@dev: define the rootadmin central authority 
        RootAdmin=msg.sender;
        Admins[RootAdmin] = true;
    }

    //@dev : restriction to the root admin only
    modifier onlyRootAdmin(){
        require(msg.sender == RootAdmin,"only root admin");         //@dev: changed it from msg.sender to tx.origin due to error cross calls 
        _;
    }

    //@dev : restriction to the admins only 
    modifier onlyAdmins() {
        require( Admins[tx.origin] == true ,"only admins");
        _;
    }

    //@dev: the role must be defined and exist protect agaisnt undeclared roles being push to storage 
    modifier RoleDefined(string memory _Role) {
        require(Role[_Role].check == true,"the role is not defined ");
        _;
    }

    //@dev: the input must not be empty 
    modifier NotEmptyString(string memory _Role){
        require(_isStringEmpty(_Role)== false,"the input must not be empty");
        _;
    }




    // internal functions

    //@dev: check wether the input is empty 
    function _isStringEmpty(string memory _str) internal pure returns (bool) {
        return bytes(_str).length == 0;
    }

    //@dev: compare 2 strings together 
    function _stringCompare(string memory _str1 , string memory _str2 ) internal pure returns(bool) {
        return keccak256(abi.encodePacked(_str1)) == keccak256(abi.encodePacked(_str2)) ;
    }

    //@dev: internal function 
    function _GetIndexOfRole(string memory _Role , address _address) internal view returns (int) {
        for (uint i= 0; i < Roles[_address].length;i++) {
            if (_stringCompare(Roles[_address][i],_Role)) {
                return int(i);
            }
        }
        return -1;
    }
    //@dev : get the index of the address inside the addresses list 
    function _GetIndexOfAddress(address _address) internal view returns (int) {
        for (uint i= 0; i < addresses.length ;){
            if ( _address == addresses[i]) {
                return int(i);
            }
        }
        return -1;
    }
    
    //@dev: remove user  from least and clean the list {unordered}
    function _DeleteUserFromAddresses(address _address) internal {
        addresses[uint(_GetIndexOfAddress(_address))] = addresses[addresses.length -1];
        addresses.pop();
    }
    //@dev:  // deduct the number of assignments 
    function _DeductNumber( address _address) internal {
        for ( uint256 i =0 ; i < Roles[_address].length; i++ ) {
            Role[Roles[_address][i]].number--;   // deduct the number of assignments 
        }
    }

    function _UnorderedDeleteRoles(address _address,uint256 _index) internal {
        Roles[_address][_index] = Roles[_address][Roles[_address].length -1];
        Roles[_address].pop();
    }



    //@dev: unordered delete of role ( clean delete )
    function _DeletelistallRoles (string memory _Role) internal {
        for ( uint i= 0; i < ListOfRoles.length; i++) {
            if ( _stringCompare(_Role,ListOfRoles[i])) {
                ListOfRoles[i] = ListOfRoles[ListOfRoles.length - 1 ];
                ListOfRoles.pop();
            }
        }
    }

    //@dev delete role assigned to all the addresses
    function _DeleteRole(string memory _Role) internal {
        int index;
        for(uint i = 0 ; i < addresses.length; i++){
            index = _GetIndexOfRole(_Role ,addresses[i]);
            if ( index != -1 ){
                if ( Roles[addresses[i]].length == 1 ) { delete Roles[addresses[i]];}  // this will clean the storage if the address contain only one role and the role is being removed 
                else {_UnorderedDeleteRoles(addresses[i],uint256(index));} // unordered clean of the Roles list 
            }
        }
    }    




    
    
    //external functions 


    //@dev: define existing roles and will be used later for validation
    function DeclareRole ( string memory _Role ) external RunningOnly()  onlyAdmins() NotEmptyString(_Role) {
        require(!Role[_Role].check ,"role already exist");
        Role[_Role] = role(true,0);
        ListOfRoles.push(_Role);
        emit RoleDeclared(block.timestamp,_Role);
    }
    //@dev: remove a role only if the role is not being used should be used first , and remove Role from the list using the _DeletelistallRoles()
    function RemoveRole( string memory _Role) external RunningOnly()  onlyAdmins() NotEmptyString(_Role)  {
        require(Role[_Role].check == true,"the role doesnt exist");                      //@dev require the role to be declared first (role shouldnt be removed if not declared)
        require(Role[_Role].number == 0, "the role is assigned please remove the roles or use ForceRemove"); 
        delete(Role[_Role]);
        _DeletelistallRoles(_Role);
        emit RoleRemoved(block.timestamp,_Role);
    }

    //@dev: remove defined roles , also will remove the assigned role to all the addresses  should be used as last resort 
    function ForceRemoveRole( string memory _Role) external RunningOnly() onlyRootAdmin() {
        require(Role[_Role].check == true  , "role doesn't exist");
        _DeleteRole(_Role);                // this function will delete all associated role if address have only one role it will be removed with the role 
        _DeletelistallRoles(_Role);        // delete the role from allRoles()
        delete(Role[_Role]);               // clean the mapping 
        emit ForceRoleRemoved(block.timestamp,_Role); 
    }
    //@dev: add admin ,this admin role will be used as reference in the other contracts , the address of the admin must not be associated with any other role
    function AddAdmin(address _adminaddr ) external RunningOnly() onlyRootAdmin() {
        require(Roles[_adminaddr].length == 0,"the address is already assigned to a role");
        require(Admins[_adminaddr] == false, "admin already declared , or the address is declare with different role ");
        Admins[_adminaddr] = true ;
       emit AdminCreated(block.timestamp,_adminaddr);
    }
    //@dev: revoke admin 
    function removeAdmin(address _adminaddr) external RunningOnly() onlyRootAdmin() {
        require(Admins[_adminaddr] == true, "Address is not an admin");
        delete Admins[_adminaddr];
        emit AdminRevoked(block.timestamp,_adminaddr);
    }

        //@dev: init a user with initial role 
    function AddUser(address _address , string memory _Role) external RunningOnly()  onlyAdmins() RoleDefined(_Role) {
        require(Admins[_address] == false ,"the user is admin");
        require(Roles[_address].length == 0, "the address is already declared"); // i think this is a mistake 
        require(_GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        Roles[_address].push(_Role);
        Role[_Role].number++; // track the number of association 
        addresses.push(_address);
        emit UserCreated(block.timestamp,_address,_Role);
    }

    //@dev : completely remove a user 
    function RemoveUser(address _address) external RunningOnly() onlyAdmins() {
        // add rules here shoudlnt remove admin 
        delete Roles[_address];
        _DeleteUserFromAddresses(_address);
        _DeductNumber(_address);
        emit UserRemoved(block.timestamp,_address);
    }

    //@dev: add a role to a user 
    function AddRoleUser(address _address , string memory _Role) external RunningOnly() onlyAdmins() RoleDefined(_Role)  {
        require(Roles[_address].length >= 1, " the address must be declared first");
        require(_GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        Roles[_address].push(_Role);
        emit UserAddRole(block.timestamp,_address,_Role);
    }
    //@dev : remove a specific role 
    function RemoveRoleUser(address _address , string memory _Role) external RunningOnly() onlyAdmins() RoleDefined(_Role)  {
        require(Roles[_address].length > 1, " the address must be declared first , the address must have more then one role ");   //@dev no Address shoud live in the storage without Role , if you want to remove the user use deleteUser 
        require(_GetIndexOfRole(_Role,_address) >= 0,"the Role doesnt exist");
        Roles[_address][uint(_GetIndexOfRole(_Role,_address))] = Roles[_address][Roles[_address].length - 1 ]; // unordered remove clean lists
        Roles[_address].pop();
        _UnorderedDeleteRoles(_address,uint(_GetIndexOfRole(_Role,_address)));
        emit UserRoleRevoked(block.timestamp,_address,_Role);
    }
    //@dev : will be used for modifier in other contract to check wether the msg.sender has a Role 
    function CheckAssignedRole(address _address, string memory _Role) external RunningOnly() view returns(bool) {
        if(_GetIndexOfRole(_Role,_address) != -1 ) {
            return true;
        }
        return false; 
    }

    function CheckAdmins(address _address) external RunningOnly() view   returns(bool) {
        return Admins[_address];
    }           

        //@dev: administrator dashboard Front UI functions 
        // most of this function will be removed later because it will be implemnted with a web3 
    //@dev : list all associated roles for address 
    function ListallRolesByAddress(address _address) external RunningOnly() view returns(string[] memory) {
        return Roles[_address];
    }


    // public functions
    //@dev: check wether the role declared or not 
    function _RoleExist(string memory _Role) public RunningOnly() view returns (bool) {
        for ( uint i = 0; i < addresses.length; i++){
            if ( _GetIndexOfRole(_Role,addresses[i]) != -1) {
                return true;
            }
        }
        return false;
    }


    /* NOT WORTH IT 
    //@dev : this will be used for dashboard list the Front will feed the _Role for optimization instead of writing another function for admin listing 
    function listallbyRole(string memory _Role) external view returns (address[] memory) {
        if (keccak256(bytes(_Role)) == keccak256(bytes("admin"))) { 
            require(msg.sender == rootadmin, "Access denied");
        }
        address[] memory outputaddresses= new address[](_GetTotalAssociatedRole(_Role));
        uint256 count = 0;
        for (uint256 i = 0; i < addresses.length; i++) {
            if (_GetIndexOfRole(_Role, addresses[i]) != -1) {
                outputaddresses[count] = addresses[i];
                count++;
            }
        }
        return outputaddresses;
    }
    */


    //@dev : list all roles 
    function ListAllRoles() external RunningOnly() view returns (string[] memory) {
        string[] memory AllRoles = new string[](ListOfRoles.length);
        for ( uint i = 0 ; i < ListOfRoles.length; i++) {
            AllRoles[i] = ListOfRoles[i];
        }
        return AllRoles;
    }

}
