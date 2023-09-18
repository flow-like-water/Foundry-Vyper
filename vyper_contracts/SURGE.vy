# @version ^0.3.9
"""
@title SURGE Token
@license MIT
@author Water
"""

from vyper.interfaces import ERC20
implements: ERC20

from vyper.interfaces import ERC20Detailed
implements: ERC20Detailed

import interfaces.IERC20Permit as IERC20Permit
implements: IERC20Permit

from interfaces.IERC5267 import IERC5267
implements: IERC5267

_MALLEABILITY_THRESHOLD: constant(bytes32) = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
_TYPE_HASH: constant(bytes32) = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_PERMIT_TYPE_HASH: constant(bytes32) = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")

_CACHED_DOMAIN_SEPARATOR: immutable(bytes32)
_CACHED_CHAIN_ID: immutable(uint256)
_CACHED_SELF: immutable(address)

_NAME: immutable(String[50])
_HASHED_NAME: immutable(bytes32)
_VERSION: immutable(String[20])
_HASHED_VERSION: immutable(bytes32)
MAX_LENGTH: constant(uint256) = 2048

# State variables
decimals: public(constant(uint8)) = 18
name: public(immutable(String[25]))
symbol: public(immutable(String[5]))

balanceOf: public(HashMap[address, uint256])
allowance: public(HashMap[address, HashMap[address, uint256]])
totalSupply: public(uint256)
is_minter: public(HashMap[address, bool])
nonces: public(HashMap[address, uint256])

owner: public(address)
treasury: public(address)
mint_lock_time: public(uint256)
mint_start_time: public(uint256)
mint_expiration_time: public(uint256)
mints: public(HashMap[address, uint256])

# Events
event Transfer:
    owner: indexed(address)
    to: indexed(address)
    amount: uint256

event Approval:
    owner: indexed(address)
    spender: indexed(address)
    amount: uint256

event Mint:
    minter: indexed(address)
    amount: uint256

event EIP712DomainChanged:
    pass

event OwnershipTransferred:
    previous_owner: indexed(address)
    new_owner: indexed(address)

event RoleMinterChanged:
    minter: indexed(address)
    status: bool

@external
@payable
def __init__(name_: String[25], symbol_: String[5], initial_supply_: uint256, name_eip712_: String[50], version_eip712_: String[20], treasury_: address, mint_lock_time_: uint256, mint_start_time_: uint256, mint_expiration_time_: uint256):
    assert mint_lock_time_ < mint_start_time_, "Mint should not start before the tokens are locked"
    assert mint_start_time_ < mint_expiration_time_, "Mint should not expire before it starts"

    initial_supply: uint256 = initial_supply_ * 10 ** convert(decimals, uint256)
    name = name_
    symbol = symbol_
    self.treasury = treasury_
    self.mint_lock_time = mint_lock_time_
    self.mint_start_time = mint_start_time_
    self.mint_expiration_time = mint_expiration_time_

    self._transfer_ownership(msg.sender)
    self.is_minter[msg.sender] = True
    log RoleMinterChanged(msg.sender, True)

    if (initial_supply != empty(uint256)):
        self._before_token_transfer(empty(address), msg.sender, initial_supply)
        self.totalSupply = initial_supply
        self.balanceOf[msg.sender] = initial_supply
        log Transfer(empty(address), msg.sender, initial_supply)
        self._after_token_transfer(empty(address), msg.sender, initial_supply)

    _NAME = name_eip712_
    _VERSION = version_eip712_
    _HASHED_NAME = keccak256(name_eip712_)
    _HASHED_VERSION = keccak256(version_eip712_)
    _CACHED_DOMAIN_SEPARATOR = self._build_domain_separator()
    _CACHED_CHAIN_ID = chain.id
    _CACHED_SELF = self


@external
def transfer(to: address, amount: uint256) -> bool:
    assert block.timestamp >= self.mint_start_time, "Cannot transfer before the mint starts"
    self._transfer(msg.sender, to, amount)
    return True


@external
def approve(spender: address, amount: uint256) -> bool:
    assert block.timestamp >= self.mint_start_time, "Cannot approve before the mint starts"
    self._approve(msg.sender, spender, amount)
    return True


@external
def transferFrom(owner: address, to: address, amount: uint256) -> bool:
    assert block.timestamp >= self.mint_start_time, "Cannot transferFrom before the mint starts"
    self._spend_allowance(owner, msg.sender, amount)
    self._transfer(owner, to, amount)
    return True


@external
def burn(amount: uint256):
    assert block.timestamp >= self.mint_start_time, "Cannot burn before the mint starts"
    self._burn(msg.sender, amount)


@external
def burn_from(owner: address, amount: uint256):
    assert block.timestamp >= self.mint_start_time, "Cannot burn_from before the mint starts"
    self._spend_allowance(owner, msg.sender, amount)
    self._burn(owner, amount)


@external
def mint_of(account: address) -> uint256:
    return self.mints[account]


@external
def mint(owner: address, amount: uint256):
    assert block.timestamp >= self.mint_start_time, "Cannot mint before the mint starts"
    assert self.is_minter[msg.sender], "AccessControl: access is denied"
    self._mint(owner, amount)


@external
def mint_treasury(treasury: address) -> bool:
    self._check_owner()

    mint_amount: uint256 = self.mints[treasury]
    assert mint_amount > 0, "SURGE: nothing to mint"

    self._mint(treasury, mint_amount)
    self.mints[treasury] = 0

    return True


@external
def set_minter(minter: address, status: bool):
    self._check_owner()
    assert minter != empty(address), "AccessControl: minter is the zero address"
    assert minter != msg.sender, "AccessControl: minter is owner address"
    self.is_minter[minter] = status
    log RoleMinterChanged(minter, status)


@external
def set_mint(account: address, amount: uint256):
    self._check_owner()
    # Check that it's not setting for treasury and time lock conditions, if any
    assert account != self.treasury, "Should not adjust mint amount for treasury"
    assert block.timestamp < self.mint_lock_time, "Cannot set mint amount after mint locked"

    current_amount: uint256 = self.mints[account]

    # Adjust the treasury's mintable amount
    self.mints[self.treasury] = self.mints[self.treasury] + current_amount - amount

    # Record new amount or delete the key if amount is zero
    if amount == 0:
        self.mints[account] = 0
    else:
        self.mints[account] = amount

@external
def set_mints(accounts: DynArray[address, MAX_LENGTH], amounts: DynArray[uint256, MAX_LENGTH]): 
    self._check_owner()
    assert block.timestamp < self.mint_lock_time, "Cannot set mint amount after mint locked"
    assert len(accounts) == len(amounts), "Input mismatch"

    for i in range(MAX_LENGTH):
        account: address = accounts[i]
        amount: uint256 = amounts[i]

        if account == ZERO_ADDRESS:
            break
        
        assert account != self.treasury, "Should not adjust mint amount for treasury"

        current_amount: uint256 = self.mints[account]

        # Ensure the treasury has enough to deduct
        assert self.mints[self.treasury] >= (current_amount - amount), "Amount exceeds maximum allowance"

        # Adjust treasury's mintable amount
        self.mints[self.treasury] = self.mints[self.treasury] + current_amount - amount

        # Record the new amount
        if amount == 0:
            self.mints[account] = 0  # Effectively deleting the mapping entry
        else:
            self.mints[account] = amount


@external
def add_mint(account: address, amount: uint256):
    self._check_owner()
    assert block.timestamp < self.mint_lock_time, "Cannot add mint amount after mint locked"
    assert amount > 0, "Meaningless to add zero amount"
    assert account != self.treasury, "Should not adjust mint amount for treasury"

    # Ensure that the treasury has enough to deduct
    assert self.mints[self.treasury] >= amount, "Amount exceeds maximum allowance"

    # Adjust the treasury's mintable amount
    self.mints[self.treasury] -= amount

    # Record the new amount
    self.mints[account] += amount
    

@external
def permit(owner: address, spender: address, amount: uint256, deadline: uint256, v: uint8, r: bytes32, s: bytes32):
    
    assert block.timestamp <= deadline, "ERC20Permit: expired deadline"

    current_nonce: uint256 = self.nonces[owner]
    self.nonces[owner] = unsafe_add(current_nonce, 1)

    struct_hash: bytes32 = keccak256(_abi_encode(_PERMIT_TYPE_HASH, owner, spender, amount, current_nonce, deadline))
    hash: bytes32  = self._hash_typed_data_v4(struct_hash)

    signer: address = self._recover_vrs(hash, convert(v, uint256), convert(r, uint256), convert(s, uint256))
    assert signer == owner, "ERC20Permit: invalid signature"

    self._approve(owner, spender, amount)


@external
@view
def DOMAIN_SEPARATOR() -> bytes32:
    return self._domain_separator_v4()


@external
@view
def EIP712Domain() -> (bytes1, String[50], String[20], uint256, address, bytes32, DynArray[uint256, 128]):

    # Note that `\x0f` equals `01111`.
    return (convert(b"\x0f", bytes1), _NAME, _VERSION, chain.id, self, empty(bytes32), empty(DynArray[uint256, 128]))

# transferTreasury
@external
def transfer_ownership(new_owner: address):

    self._check_owner()

    mint_amount: uint256 = self.mints[self.owner]
    
    assert new_owner != empty(address), "Ownable: new owner is the zero address"

    self.is_minter[msg.sender] = False
    log RoleMinterChanged(msg.sender, False)

    self._transfer_ownership(new_owner)
    self.is_minter[new_owner] = True
    log RoleMinterChanged(new_owner, True)

    if mint_amount > 0:
        self.mints[self.owner] = 0
        self.mints[new_owner] = self.mints[new_owner] + mint_amount


@external
def renounce_ownership():
    self._check_owner()
    self.is_minter[msg.sender] = False
    log RoleMinterChanged(msg.sender, False)
    self._transfer_ownership(empty(address))


@internal
def _transfer(owner: address, to: address, amount: uint256):
    assert owner != empty(address), "ERC20: transfer from the zero address"
    assert to != empty(address), "ERC20: transfer to the zero address"

    self._before_token_transfer(owner, to, amount)

    owner_balanceOf: uint256 = self.balanceOf[owner]
    assert owner_balanceOf >= amount, "ERC20: transfer amount exceeds balance"
    self.balanceOf[owner] = unsafe_sub(owner_balanceOf, amount)
    self.balanceOf[to] = unsafe_add(self.balanceOf[to], amount)
    log Transfer(owner, to, amount)

    self._after_token_transfer(owner, to, amount)


@internal
def _mint(owner: address, amount: uint256):
    assert owner != empty(address), "ERC20: mint to the zero address"

    self._before_token_transfer(empty(address), owner, amount)

    self.totalSupply += amount
    self.balanceOf[owner] = unsafe_add(self.balanceOf[owner], amount)
    log Transfer(empty(address), owner, amount)

    self._after_token_transfer(empty(address), owner, amount)


@internal
def _burn(owner: address, amount: uint256):
    assert owner != empty(address), "ERC20: burn from the zero address"

    self._before_token_transfer(owner, empty(address), amount)

    account_balance: uint256 = self.balanceOf[owner]
    assert account_balance >= amount, "ERC20: burn amount exceeds balance"
    self.balanceOf[owner] = unsafe_sub(account_balance, amount)
    self.totalSupply = unsafe_sub(self.totalSupply, amount)
    log Transfer(owner, empty(address), amount)

    self._after_token_transfer(owner, empty(address), amount)


@internal
def _approve(owner: address, spender: address, amount: uint256):
    assert owner != empty(address), "ERC20: approve from the zero address"
    assert spender != empty(address), "ERC20: approve to the zero address"

    self.allowance[owner][spender] = amount
    log Approval(owner, spender, amount)


@internal
def _spend_allowance(owner: address, spender: address, amount: uint256):
    current_allowance: uint256 = self.allowance[owner][spender]
    if (current_allowance != max_value(uint256)):
        # The following line allows the commonly known address
        # poisoning attack, where `transferFrom` instructions
        # are executed from arbitrary addresses with an `amount`
        # of 0.
        assert current_allowance >= amount, "ERC20: insufficient allowance"
        self._approve(owner, spender, unsafe_sub(current_allowance, amount))


@internal
def _before_token_transfer(owner: address, to: address, amount: uint256):
    pass


@internal
def _after_token_transfer(owner: address, to: address, amount: uint256):
    pass


@internal
def _check_owner():
    assert msg.sender == self.owner, "Ownable: caller is not the owner"


@internal
def _transfer_ownership(new_owner: address):
    old_owner: address = self.owner
    self.owner = new_owner
    log OwnershipTransferred(old_owner, new_owner)


@internal
@view
def _domain_separator_v4() -> bytes32:
    if (self == _CACHED_SELF and chain.id == _CACHED_CHAIN_ID):
        return _CACHED_DOMAIN_SEPARATOR
    else:
        return self._build_domain_separator()


@internal
@view
def _build_domain_separator() -> bytes32:
    return keccak256(_abi_encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, chain.id, self))


@internal
@view
def _hash_typed_data_v4(struct_hash: bytes32) -> bytes32:
    return self._to_typed_data_hash(self._domain_separator_v4(), struct_hash)


@internal
@pure
def _to_typed_data_hash(domain_separator: bytes32, struct_hash: bytes32) -> bytes32:
    return keccak256(concat(b"\x19\x01", domain_separator, struct_hash))


@internal
@pure
def _recover_vrs(hash: bytes32, v: uint256, r: uint256, s: uint256) -> address:
    return self._try_recover_vrs(hash, v, r, s)


@internal
@pure
def _try_recover_vrs(hash: bytes32, v: uint256, r: uint256, s: uint256) -> address:
    assert s <= convert(_MALLEABILITY_THRESHOLD, uint256), "ECDSA: invalid signature `s` value"

    signer: address = ecrecover(hash, v, r, s)
    assert signer != empty(address), "ECDSA: invalid signature"

    return signer