# Centralized-Role-Control
Missing intergration (WIP)

This code is a Solidity smart contract that implements a centralized Role Based Access Control (RBAC) system.
Introducing a decentralized solution for managing access control in supply chain and value chain systems. Our contract, built on the Ethereum blockchain using Solidity, provides a centralized role-based access control mechanism. The contract allows the root admin to define, remove, and manage roles for users and admins, and also provides protection against data dumping.
The contract includes functions to declare roles, add or remove admins, add or remove roles to users, and revoke user roles. It also includes events that can be used to monitor the changes to the roles and users in the contract.
The contract is secured by access modifiers that ensure that only the root admin can declare roles, and only non-admin users can be added or revoked roles. Additionally, it checks that admins cannot be associated with any other roles, and that a role can only be removed if it is not assigned to any user.
this contract can be used to manage access to various functions or features within a decentralized application (dApp) or blockchain-based system.
Overall, the contract provides a simple way to manage and control access to a system by defining different roles and assigning them to users. However, it's worth noting that it's a centralized system, and any changes to the roles or users must be made by the root admin.

action are defined within the smart contract logic but must first check wether the Roles are associated 

End of Study project 
![roleaccess drawio](https://user-images.githubusercontent.com/124497891/232068142-4e73cbcb-1b1e-4559-8e07-935af2946035.png)

