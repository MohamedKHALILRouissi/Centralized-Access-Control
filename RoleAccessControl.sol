//SPDX-License-Identifier: opensource
// @authors:   mohamed khalil rouissi    mohamed amine ghodhbene 
// @description: centralized role based access control 
// @missing : interface for the contract 



pragma solidity ^0.8.0;

contract Role {

    //address[] addresses; 
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

    function GetIndexOfRole(string memory _Role , address _address) internal view returns (int) {
        for (uint i= 0; i < roles[_address].length ; i++) {
            if (keccak256(bytes(roles[_address][i])) == keccak256(bytes(_Role))) {
                return int(i);
            }
        }
        return -1;
    }
    //@dev: define existing roles and will be used later for validation
    function DeclareRole ( string memory _Role ) external onlyAdmin() {
        require(!role[_Role] ,"role already exist");
        role[_Role]=true;
    }

    //@dev: remove defined roles
    function RemoveRole( string memory _Role) external onlyAdmin() {
        require(role[_Role] == true  , "role doesn't exist");
        delete(role[_Role]);
    }

    //@dev: add admin ,this admin role will be used as reference in the other contracts , the address of the admin must not be associated with any other role
    function AddAdmin(address _adminaddr ) external onlyAdmin() {
        require(roles[_adminaddr].length == 0, "admin already declared , or the address is declare with different role ");
        roles[_adminaddr].push("admin");
       // addresses.push(_adminaddr); // this will be used later for retrieving all admins
    }
    //@dev: revoke admin 
    function removeAdmin(address _adminaddr) external onlyAdmin() {
        require(roles[_adminaddr].length == 1 && keccak256(bytes(roles[_adminaddr][0])) == keccak256(bytes("admin")), "Address is not an admin");
        delete roles[_adminaddr];
    }
    
    //@dev: init a user with initial role 
    function AddUser(address _address , string memory _Role) external  onlyAdmin() RoleDefined(_Role) {
        require(roles[_address].length == 0, "the address is already declared"); // adminGuard
        require(GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        roles[_address].push(_Role);
    }

    //@dev : completely remove a user 
    function RemoveUser(address _address) external onlyAdmin() AdminGuard(_address) {
        delete roles[_address];
    }

    //@dev: add a role to a user 
    function AddRoleUser(address _address , string memory _Role) external onlyAdmin() RoleDefined(_Role) AdminGuard(_address) {
        require(roles[_address].length >= 1, " the address must be declared first");
        require(GetIndexOfRole(_Role,_address) == -1,"the role already exist for this user");
        roles[_address].push(_Role);
    }
    //@dev : remove a specific role 
    function RemoveRoleUser(address _address , string memory _Role) external onlyAdmin() RoleDefined(_Role) AdminGuard(_address) {
        require(roles[_address].length >= 1, " the address must be declared first , the address must have more then one role ");
        require(GetIndexOfRole(_Role,_address) >= 0,"the Role doesnt exist");
        roles[_address][uint(GetIndexOfRole(_Role,_address))] = roles[_address][roles[_address].length - 1 ]; // unordered remove clean lists
        roles[_address].pop();
    }
    //@dev : list all associated roles for address 
    function ListRolesByAddress(address _address) external view returns(string[] memory) {
        return roles[_address];
    }
    
    //@dev : list all address associated to a role ( for front UI ) 
    // WIP
    //@dev : list all admins ( for front UI )
    function ListAllAdmins() external view onlyAdmin() returns(address[] memory) {
    // WIP
    }
    
    //@dev map IoT devices to the owner 

}
