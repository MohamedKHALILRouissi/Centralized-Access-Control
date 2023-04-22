//SPDX-License-Identifier: opensource
// @authors:   mohamed khalil rouissi    mohamed amine ghodhbene 
// @description: pausable security layer 
/*
 * used by only root admin to stop and start contracts , stop contract if any bug identified 
*/


pragma solidity ^0.8.0;
   
   /* the contract is always running by default   */

abstract contract PausableLayer {   
    event PauseContractCRBAC(uint256 timestamp,string reason);
    event StartContratCRBAC(uint256 timestamp);
    bool public state;
    constructor() {
        state = true;
    }


    modifier RunningOnly() {
        require(state == true,"the contract must be running");
        _;
    }

    function pause(string memory _reason) external virtual  {
        require(state == true,"can only be pressed when the contract is running");
        state = false;
        emit PauseContractCRBAC(block.timestamp,_reason);
    }

    function restart() external virtual   {
        require(state == false,"can only be pressed when the contract is paused");
        state = true;
        emit StartContratCRBAC(block.timestamp);
    }
}
