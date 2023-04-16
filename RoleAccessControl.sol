//SPDX-License-Identifier: opensource
// @authors:   mohamed khalil rouissi    mohamed amine ghodhbene 
// @description: centralized role based access control 
// @missing : interface for the contract 



pragma solidity ^0.8.0;

contract CentralizedRoleBasedAccessControl {


    event UserRoleRevoked(uint256 timestamp, address _address, string _Role);
    event UserAddRole(uint256 timestamp, address _address, string _Role);
    event ForceRoleRemoved(uint256 timestamp, string _Role);
    event UserRemoved(uint256 timestamp, address _address);
    event UserCreated(uint256 timestamp, address _address, string _Role);
    event AdminRevoked(uint256 timestamp, address _address);   
    event AdminCreated(uint256 timestamp, address _address);
    event RoleRemoved(uint256 timestamp, string _Role);
    event RoleDeclared(uint256 timestamp, string _Role);
    


    address[] addresses; 
    address internal rootadmin;
    mapping(string => bool) public role;
    mapping(address => string[]) internal roles;  //@dev this will proctect the information from total data dumping
    constructor(){
        rootadmin=msg.sender;
    }

    //@dev: define the rootadmin central authority 
    modifier onlyAdmin(){
        require(msg.sender == rootadmin,"only root admin");
        _;
    }
    

    modifier RoleDefined(string memory _Role) {
        require(role[_Role] == true,"the role is not defined ");
        _;
    }

    //@dev: protect admins
    modifier AdminGuard(address _address) {
        require(keccak256(bytes(roles[_address][0])) != keccak256(bytes("admin")), "Address is an admin");
        _;
    }

    //@dev: internal function 
    function _GetIndexOfRole(string memory _Role , address _address) internal view returns (int) {
        for (uint i= 0; i < roles[_address].length;i++) {
            if (keccak256(bytes(roles[_address][i])) == keccak256(bytes(_Role))) {
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

    //@dev: remove user or admin from least and clean the list {unordered}
    function _DeleteUserOrAdmin(address _address) internal {
        addresses[uint(_GetIndexOfAddress(_address))] = addresses[addresses.length -1];
        addresses.pop();
    }

    function _RoleExist(string memory _Role) internal view returns (bool) {
        for ( uint i = 0; i < addresses.length; i++){
            if ( _GetIndexOfRole(_Role,addresses[i]) != -1) {
                return true;
            }
        }
        return false;
    }

    //@dev delete role assigned to all the addresses
    function _DeleteRole(string memory _Role) internal {
        int index;
        for(uint i = 0 ; i < addresses.length; i++){
            index = _GetIndexOfRole(_Role ,addresses[i]);
            if ( index != -1 ){
                roles[addresses[i]][uint(index)] = roles[addresses[i]][roles[addresses[i]].length - 1 ];
                roles[addresses[i]].pop();
            }
        }
    }

    function _GetTotalAssociatedRole(string memory _Role) internal view returns (uint){
        uint y = 0;
        for (uint i = 0; i < addresses.length; i++ ) {
            if ( _GetIndexOfRole(_Role,addresses[i]) != -1 ) {
                y++;
            }
        }
        return y;
    }



    //@dev: define existing roles and will be used later for validation
    function DeclareRole ( string memory _Role ) external onlyAdmin() {
        require(!role[_Role] ,"role already exist");
        role[_Role]=true;
        emit RoleDeclared(block.timestamp,_Role);
    }

    //@dev : remove a role only if the role is not being used should be used first 
    function removeRole( string memory _Role) external onlyAdmin() {
        require(_RoleExist(_Role) == false,"the role is assigned you should remove the role or use ForceRemove"); // SAFE REMOVE 
        delete(role[_Role]);
        emit RoleRemoved(block.timestamp,_Role);
    }


    //@dev: remove defined roles , also will remove the assigned role to all the addresses  should be used as last resort 
    function ForceRemoveRole( string memory _Role) external onlyAdmin() {
        require(role[_Role] == true  , "role doesn't exist");
        delete(role[_Role]);
        _DeleteRole(_Role);
        emit ForceRoleRemoved(block.timestamp,_Role);
        


    }

    //@dev: add admin ,this admin role will be used as reference in the other contracts , the address of the admin must not be associated with any other role
    function AddAdmin(address _adminaddr ) external onlyAdmin() {
        require(roles[_adminaddr].length == 0, "admin already declared , or the address is declare with different role ");
        roles[_adminaddr].push("admin");
       // addresses.push(_adminaddr); // this will be used later for retrieving all admins
       emit AdminCreated(block.timestamp,_adminaddr);
    }
    //@dev: revoke admin 
    function removeAdmin(address _adminaddr) external onlyAdmin() {
        require(roles[_adminaddr].length == 1 && keccak256(bytes(roles[_adminaddr][0])) == keccak256(bytes("admin")), "Address is not an admin");
        delete roles[_adminaddr];
        _DeleteUserOrAdmin(_adminaddr); 
        emit AdminRevoked(block.timestamp,_adminaddr);
    }
    
    //@dev: init a user with initial role 
    function AddUser(address _address , string memory _Role) external  onlyAdmin() RoleDefined(_Role) {
        require(roles[_address].length == 0, "the address is already declared"); // adminGuard
        require(_GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        roles[_address].push(_Role);
        addresses.push(_address);
        emit UserCreated(block.timestamp,_address,_Role);
    }

    //@dev : completely remove a user 
    function RemoveUser(address _address) external onlyAdmin() AdminGuard(_address) {
        // add rules here shoudlnt remove admin 
        delete roles[_address];
        _DeleteUserOrAdmin(_address);
        emit UserRemoved(block.timestamp,_address);
    }

    //@dev: add a role to a user 
    function AddRoleUser(address _address , string memory _Role) external onlyAdmin() RoleDefined(_Role) AdminGuard(_address) {
        require(roles[_address].length >= 1, " the address must be declared first");
        require(_GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        roles[_address].push(_Role);
        emit UserAddRole(block.timestamp,_address,_Role);
    }
    //@dev : remove a specific role 
    function RemoveRoleUser(address _address , string memory _Role) external onlyAdmin() RoleDefined(_Role) AdminGuard(_address) {
        require(roles[_address].length >= 1, " the address must be declared first , the address must have more then one role ");
        require(_GetIndexOfRole(_Role,_address) >= 0,"the Role doesnt exist");
        roles[_address][uint(_GetIndexOfRole(_Role,_address))] = roles[_address][roles[_address].length - 1 ]; // unordered remove clean lists
        roles[_address].pop();
        emit UserRoleRevoked(block.timestamp,_address,_Role);
    }

        //@dev: administrator dashboard Front UI functions 

    //@dev : list all associated roles for address 
    function ListallRolesByAddress(address _address) external view returns(string[] memory) {
        return roles[_address];
    }

    //@dev : list all roles 

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
    //@dev IoT access control 
    
}
