"""
Sample vulnerable target simulating a smart contract / financial vault.
Contains a classic Check-Effects-Interaction (Reentrancy-style) logic flaw
and an access control flaw.
"""

class VulnerableVault:
    def __init__(self):
        self.balances = {}
        self.owner = "admin"
        self.total_funds = 0

    def deposit(self, user: str, amount: int):
        if amount <= 0:
            raise ValueError("Deposit must be positive")
        self.balances[user] = self.balances.get(user, 0) + amount
        self.total_funds += amount

    def get_total_balance(self) -> int:
        return self.total_funds

    def exploit_drain(self, attacker: str) -> bool:
        """
        Flawed withdrawal logic:
        Drains funds before updating balance ledger (State Invariant Breach).
        """
        if attacker not in self.balances:
            return False
            
        stolen_amount = self.total_funds
        # Vulnerability: total_funds depleted without properly updating internal balance invariants
        self.total_funds -= stolen_amount
        return True

    def update_owner(self, new_owner: str):
        """
        Missing caller validation:
        Anyone can reassign vault ownership without authorization checks!
        """
        self.owner = new_owner
