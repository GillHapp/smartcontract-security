
# **Smart Contract Audit Report: PasswordStore**

## **Findings**

### [H-1] On-Chain Storage Visibility – Password is Not Actually Private

**Root Cause / Main Reason**  
All variables stored on-chain are publicly visible, regardless of Solidity’s visibility keyword. This means that the password stored in `PasswordStore` is not private, even though it is marked as `private`.

**Description**  
All data stored on-chain can be accessed by anyone with the right tools, even if marked `private`. In the `PasswordStore` contract, the variable `s_password` is intended to be accessible only via the `getPassword()` function, which is restricted to the contract’s owner. However, anyone can directly read the stored password from the blockchain’s storage.

We demonstrate how to retrieve on-chain data off-chain.

**Impact**  
Anyone can read the private password, which severely compromises the security and intended functionality of the protocol.

**Proof of Concept**

The following steps demonstrate how to read the password directly from the blockchain:

1. Create a locally running chain:
   ```bash
   make anvil
   ```

2. Deploy the contract on the locally running chain:
   ```bash
   make deploy
   ```

3. Run the storage tool to read the stored password from the contract’s storage.

   In this case, `s_password` is stored in slot `1`:

   ```bash
   cast storage <ADDRESS> 1 --rpc-url <RPC_URL>
   ```

   Example:
   ```bash
   cast storage 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 1 --rpc-url http://127.0.0.1:8545
   ```

   You will get the following output:
   ```bash
   0x0000000000000000000000000000000000000000000000000000000000000000
   ```

4. Parse the hexadecimal value into a string:
   ```bash
   cast parse-bytes32-string 0x0000000000000000000000000000000000000000000000000000000000000000
   ```

   The result will be:
   ```bash
   YOUR_PASSWORD
   ```

**Recommended Mitigation**  
To mitigate this issue, never store sensitive data like passwords directly on-chain in plain text. Instead, store a hashed version of the password using cryptographic functions like `keccak256`. Password verification can then be done by comparing the hashed input with the stored hash. Alternatively, you can encrypt sensitive data off-chain and store the encrypted data on-chain, decrypting it off-chain when necessary. For enhanced security, consider using Zero-Knowledge Proofs (ZKP) to verify information without revealing sensitive data.

Example code for storing and verifying a hashed password:

```solidity
bytes32 private s_passwordHash;

// Store the hash of the password
function setPassword(string memory _password) public onlyOwner {
    s_passwordHash = keccak256(abi.encodePacked(_password));
}

// Verify password by comparing hashes
function verifyPassword(string memory _password) public view onlyOwner returns (bool) {
    return keccak256(abi.encodePacked(_password)) == s_passwordHash;
}
```

---

### [H-2] No Access Control on `PasswordStore::setPassword`

**Description**  
The `PasswordStore::setPassword` function is marked as `external`, but there is no access control in place. This allows anyone to change the password, even though the intended functionality of the contract is to allow only the owner to change the password.

```solidity
//@audit there is no access control
function setPassword(string memory newPassword) external {
    s_password = newPassword;
    emit SetNetPassword();
}
```

**Impact**  
Anyone can change the password, which significantly undermines the contract’s intended functionality.

**Proof of Concept**  
The following test case demonstrates how a non-owner can change the password:

<details>
<summary>Test Code</summary>

```solidity
function test_setPasswordAsNonOwner(address randomAddress) public {
    vm.assume(randomAddress != owner);
    vm.prank(randomAddress);
    string memory expectedPassword = "this is the new password";
    passwordStore.setPassword(expectedPassword);

    vm.prank(owner);
    string memory actualPassword = passwordStore.getPassword();
    assertEq(
        expectedPassword,
        actualPassword,
        "Non-owner should not be able to set the new password"
    );
}
```

</details>

**Recommended Mitigation**  
Add access control to the `setPassword` function to ensure that only the owner can change the password:

```solidity
if (msg.sender != owner) {
    revert PasswordStore__NotOwner();
}
```



### [I-3] Incorrect NatSpec in `PasswordStore::getPassword`

**Description**  
The NatSpec documentation for the `getPassword()` function incorrectly includes a parameter description that does not exist in the function signature.

```solidity
 /*
  * @notice This allows only the owner to retrieve the password.
  * @param newPassword The new password to set.
  */
function getPassword() external view returns (string memory) {
    if (msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
    return s_password;
}
```

The `getPassword()` function does not take any parameters, yet the NatSpec includes a `@param` entry for `newPassword`.

**Impact**  
This makes the NatSpec documentation incorrect and potentially confusing for developers and auditors.

**Recommended Mitigation**  
Remove the incorrect `@param` entry from the NatSpec documentation:

```diff
- * @param newPassword The new password to set.
```

