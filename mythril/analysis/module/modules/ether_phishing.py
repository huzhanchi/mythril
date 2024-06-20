import logging
from copy import copy

from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.potential_issues import (
    get_potential_issues_annotation,
    PotentialIssue,
)
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.analysis.swc_data import UNPROTECTED_ETHER_WITHDRAWAL
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis import solver
from mythril.exceptions import UnsatError
from mythril.laser.smt import UGT
from mythril.laser.smt import BitVec, symbol_factory
from mythril.laser.smt.bool import And

log = logging.getLogger(__name__)

DESCRIPTION = """
Check if the contact can be 'accidentally' killed by anyone.
For kill-able contracts, also check whether it is possible to direct the contract balance to the attacker.
"""


class EtherPhishing(DetectionModule):
    """This module search for cases where Ether can be withdrawn to a user-
    specified address."""

    name = "Any sender can withdraw ETH from the contract account"
    swc_id = UNPROTECTED_ETHER_WITHDRAWAL
    description = DESCRIPTION
    entry_point = EntryPoint.CALLBACK
    post_hooks = ["CALL", "STATICCALL"]

    def __init__(self):
        super().__init__()
        self._cache_address = {}

    def reset_module(self):
        """
        Resets the module
        :return:
        """
        super().reset_module()

    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """
        # return self._analyze_state(state)
        potential_issues = self._analyze_state(state)

        annotation = get_potential_issues_annotation(state)
        annotation.potential_issues.extend(potential_issues)

    def _analyze_state(self, state):
        """
        :param state:
        :return:
        """
        state = copy(state)
        instruction = state.get_current_instruction()

        constraints = copy(state.world_state.constraints)
     
        zero = symbol_factory.BitVecVal(0, 256)
        sender = state.environment.sender
        constraints += [
            And(state.world_state.balances[sender] == zero, UGT(state.world_state.starting_balances[sender], zero))
        ]

        try:
            # Pre-solve so we only add potential issues if the attacker's balance is increased.

            solver.get_model(constraints)
            potential_issue = PotentialIssue(
                contract=state.environment.active_account.contract_name,
                function_name=state.environment.active_function_name,
                address=instruction["address"]
                - 1,  # In post hook we use offset of previous instruction
                swc_id=UNPROTECTED_ETHER_WITHDRAWAL,
                title="Unprotected Ether Withdrawal All balance",
                severity="High",
                bytecode=state.environment.code.bytecode,
                description_head="A victim also as an MEV evil conctract creator withdraw all their Ether to the scammer from their contract account.",
                description_tail="The MEV searcher was lured by a scammer on social networks to publish malicious MEV bot contract code on online IDEs such as Remi\n"
                "and was induced to initiate a transaction, transferring all of their balance to the scammer's address, resulting in the victim's loss.",
                detector=self,
                constraints=constraints,
            )
            self.issues

            return [potential_issue]
        except UnsatError:
            return []


detector = EtherPhishing()
