/*
unit test
*/


const RBAC = artifacts.require("rbac");
contract("rbac", function(accounts) {
  let rbac;
  beforeEach(async function() {
    rbac = await RBAC.new();
  });



  ///////// Test case for declaring a role        ( passed )
  it("should declare a new role", async function() {
    // Declare a new role 
    const roleName = "admin";
    await rbac.DeclareRole(roleName);

    // Check that the role was declared
    const isRoleDeclared = await rbac.Role(roleName);
    assert.isTrue(isRoleDeclared.check, "Role was not declared");
  });

   ///////// Failing Test case for declaring a role multiple time       
    it("SHOULDNT declare an existing role", async function() {
      // Declare a new role 
      const roleName = "admin";
      await rbac.DeclareRole(roleName);

      try {
        await rbac.DeclareRole(roleName);
        throw new Error("Expected error not thrown");
      } catch (error) {
        ///NOTHING
      }

      // Check that the role was declared
      const isRoleDeclared = await rbac.Role(roleName);
      assert.isTrue(isRoleDeclared.check, "Role was not declared");
    });



  //////// Test case for removing a role           ( passed )
  it("should remove an existing role", async function() {
    // Declare a new role
    const roleName = "admin";
    await rbac.DeclareRole(roleName);

    // Remove the role
    await rbac.RemoveRole(roleName);

    // Check that the role was removed
    const isRoleDeclared = await rbac.Role(roleName);
    assert.isFalse(isRoleDeclared.check, "Role was not removed");
  });



  //////// Failing Test case for removing a non existing role           ( passed )
  it("SHOULDNT remove a non existing role", async function() {
    const roleName = "test";
    try {
      await rbac.RemoveRole(roleName);
      throw new Error("Expected error not thrown");
    } catch (error) {
      ///NOTHING
    }
    // Check that the role was removed
    const isRoleDeclared = await rbac.Role(roleName);
    assert.isFalse(isRoleDeclared.check, "Role was not removed");
  });



  ////////// Test case for adding a role to a user           ( passed )
  it("should add an existing role to a user ", async function() {
    // Declare a new role
    const roleName = "farmer";
    await rbac.DeclareRole(roleName);

    // Add the role to the first account
    const account = accounts[1];
    await rbac.AddUser(account, roleName);
    //await rbac.AddRoleUser(account, roleName);     ///////////// testing if the same role can be given to a user twice


    // Check that the role was added to the account
    const userRoles = await rbac.CheckAssignedRole(account,roleName);
    assert.isTrue(userRoles, roleName, "Role was not added to user");
  });


  /////////// Test case for revoking a role from a user  (the address must have atleast 2 roles)     ( passed )
  it("should revoke a role from a user", async function() {
    // Declare a new role and add it to the first account
    const roleName = "farmer";
    const roleName2= "test";
    await rbac.DeclareRole(roleName);
    await rbac.DeclareRole(roleName2);
    const account = accounts[1];
    await rbac.AddUser(account, roleName);
    await rbac.AddRoleUser(account, roleName2);

    // Revoke the role from the account
    await rbac.RemoveRoleUser(account, roleName);

    // Check that the role was revoked from the account
    const userRoles = await rbac.ListallRolesByAddress(account);
    assert.notInclude( userRoles, roleName, "Role is still present ");
  });


    /////////// Failing Test case for revoking a role from a user       ( passed )
    it("SHOULDNT revoke a role from a user that only have one role", async function() {
      // Declare a new role and add it to the first account
      const roleName = "farmer";
      const roleName2 = "test";
      await rbac.DeclareRole(roleName);
      await rbac.DeclareRole(roleName2);
      const account = accounts[1];
      await rbac.AddUser(account, roleName);

      try{
        await rbac.AddRoleUser(account, roleName2);                        //////////  imitating the errored use case where one role assigned to a user will throw an error 
        throw new Error("Expected error not thrown");
      }catch (error)
        { 
          /// NOTHING 
        }
  
      // Revoke the role from the account
      
        await rbac.RemoveRoleUser(account, roleName);
     
      // Check that the role was revoked from the account
      const userRoles = await rbac.ListallRolesByAddress(account);
      assert.notInclude( userRoles, roleName, "Role is still present ");
    });



    ///////////Test case for removing a role assigned to a user       ( passed )
    it("SHOULDNT remove a role assigned to a user USE ForceRemove instead", async function() {
      // Declare a new role and add it to the first account
      const roleName = "farmer";
      await rbac.DeclareRole(roleName);
      const account = accounts[1];
      await rbac.AddUser(account, roleName);

      // Revoke the role from the account
      try {
      await rbac.removeRole(roleName);
      throw new Error("Expected Error not thrown");
      } catch (error){
        ////////////////// NOTHING 
      }         
    });


     /////////// Test case for ForceRemove       ( passed )
     it("should remove a role assigned to a user using ForceRemove", async function() {
      // Declare a new role and add it to the first account
      const roleName = "farmer";
      await rbac.DeclareRole(roleName);
      const account = accounts[1];
      await rbac.AddUser(account, roleName);
  
      // Revoke the role from the account
      await rbac.ForceRemoveRole(roleName);
      // Check that the role was revoked from the account
      const userRoles = await rbac.ListallRolesByAddress(account);
      assert.notInclude( userRoles, roleName, "Role is still present ");
    });



  ///////////////Adding multiple roles to one user                   ( passed )
  it("should add multiple roles to a user", async function() {
    // Declare two new roles
    const roleName1 = "transport";               //////////// admin can only have admin role 
    const roleName2 = "farmer";
    await rbac.DeclareRole(roleName1);
    await rbac.DeclareRole(roleName2);
  
    // Add the roles to the first account
    const account = accounts[1];
    await rbac.AddUser(account, roleName1);
    await rbac.AddRoleUser(account, roleName2);
  
    // Check that both roles were added to the account
    const userRole1 = await rbac.CheckAssignedRole(account,roleName1);
    const userRole2 = await rbac.CheckAssignedRole(account,roleName2);
    assert.isTrue(userRole1, roleName1, "Role1 was not added to user");
    assert.isTrue(userRole2, roleName2, "Role2 was not added to user");
  });


  ////////////Test case for revoking a role that is not assigned to user 
  it("SHOULDNT revoke a role that is not assigned to a user", async function() {
    // Declare a new role and add it to the first account
    const roleName = "farmer";
    await rbac.DeclareRole(roleName);
    const account = accounts[1];
    await rbac.AddUser(account, roleName);
  
    // Try to revoke a role that is not assigned to the account
    const nonAssignedRole = "admin";
    await rbac.DeclareRole(nonAssignedRole);
    try{
      await rbac.RemoveRoleUser(account, nonAssignedRole);
      throw new error ("Expected error not thrown");
    }catch (error){
       //////NOTHING
    }
    // Check that the account still has the original role
    const userRoles = await rbac.ListallRolesByAddress(account);
    assert.include(userRoles, roleName, "Original role was removed");
    assert.notInclude(userRoles, nonAssignedRole, "Non-assigned role was added");
  });


  ///////Test case listing all roles 
  it("should list all roles in the contract", async function() {
    // Declare multiple roles
    const roleNames = ["admin", "user", "moderator"];
    for (let i = 0; i < roleNames.length; i++) {                //////// remove one element from the declared roles to test the listallroles function
      await rbac.DeclareRole(roleNames[i]);
    }
  
    // Call ListAllRoles() to retrieve a list of all roles in the contract
    const allRoles = await rbac.ListAllRoles();
  
    // Check that the list contains all declared roles
    assert.equal(allRoles.length, roleNames.length, "Number of listed roles does not match declared roles");
    for (let i = 0; i < roleNames.length; i++) {
      assert.include(allRoles, roleNames[i], `Role '${roleNames[i]}' not found in list`);
    }
  });


  it("should list all roles in the contract, even if a role was removed", async function() {
    // Declare multiple roles
    const roleNames = ["admin", "user", "moderator"];
    for (let i = 0; i < roleNames.length; i++) {
      await rbac.DeclareRole(roleNames[i]);
    }
    // Remove a role
    await rbac.RemoveRole("moderator");
    
    // Call ListAllRoles() to retrieve a list of all roles in the contract
    const allRoles = await rbac.ListAllRoles();
    
    // Check that the list contains all remaining declared roles
    assert.equal(allRoles.length, roleNames.length - 1, "Number of listed roles does not match remaining declared roles");
    for (let i = 0; i < roleNames.length - 1; i++) {
      assert.include(allRoles, roleNames[i], `Role '${roleNames[i]}' not found in list`);
    }
    // Check that the removed role is not included in the list
    assert.notInclude(allRoles, "moderator", "Removed role is still listed");
  });

});



