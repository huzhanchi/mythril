from ethereum import utils
from mythril.laser.smt import (
    BitVec,
    Function,
    URem,
    symbol_factory,
    ULE,
    And,
    ULT,
    Bool,
    Or,
)
from typing import Dict, Tuple, List

TOTAL_PARTS = 10 ** 40
PART = (2 ** 256 - 1) // TOTAL_PARTS
INTERVAL_DIFFERENCE = 10 ** 30
hash_matcher = "fffffff"  # This is usually the prefix for the hash in the output


class KeccakFunctionManager:
    def __init__(self):
        self.store_function = {}  # type: Dict[int, Tuple[Function, Function]]
        self.interval_hook_for_size = {}  # type: Dict[int, int]
        self._index_counter = TOTAL_PARTS - 34534
        self.concrete_hash_vals = {}  # type: Dict[int, List[BitVec]]

    def find_keccak(self, data: BitVec) -> BitVec:
        """
        Calculates concrete keccak
        :param data: input bitvecval
        :return: concrete keccak output
        """
        keccak = symbol_factory.BitVecVal(
            int.from_bytes(
                utils.sha3(data.value.to_bytes(data.size() // 8, byteorder="big")),
                "big",
            ),
            256,
        )
        return keccak

    def get_function(self, length: int) -> Tuple[Function, Function]:
        """
        Returns the keccak functions for the corresponding length
        :param length: input size
        :return: tuple of keccak and it's inverse
        """
        try:
            func, inverse = self.store_function[length]
        except KeyError:
            func = Function("keccak256_{}".format(length), length, 256)
            inverse = Function("keccak256_{}-1".format(length), 256, length)
            self.concrete_hash_vals[length] = []
            self.store_function[length] = (func, inverse)
        return func, inverse

    def create_keccak(self, data: BitVec) -> Tuple[BitVec, Bool]:
        """
        Creates Keccak of the data
        :param data: input
        :return: Tuple of keccak and the condition it should satisfy
        """
        length = data.size()
        func, inverse = self.get_function(length)

        if data.symbolic:
            condition = self._create_condition(func_input=data)
            output = func(data)
        else:
            concrete_val = self.find_keccak(data)
            condition = And(func(data) == concrete_val, inverse(func(data)) == data)
            self.concrete_hash_vals[length].append(concrete_val)
            output = concrete_val
        return output, condition

    def _create_condition(self, func_input: BitVec) -> Bool:
        """
        Creates the constraints for hash
        :param func_input: input of the hash
        :return: condition
        """
        length = func_input.size()
        func, inv = self.get_function(length)
        try:
            index = self.interval_hook_for_size[length]
        except KeyError:
            self.interval_hook_for_size[length] = self._index_counter
            index = self._index_counter
            self._index_counter -= INTERVAL_DIFFERENCE

        lower_bound = index * PART
        upper_bound = lower_bound + PART

        cond = And(
            inv(func(func_input)) == func_input,
            ULE(symbol_factory.BitVecVal(lower_bound, 256), func(func_input)),
            ULT(func(func_input), symbol_factory.BitVecVal(upper_bound, 256)),
            URem(func(func_input), symbol_factory.BitVecVal(64, 256)) == 0,
        )
        for val in self.concrete_hash_vals[length]:
            cond = Or(cond, func(func_input) == val)
        return cond


keccak_function_manager = KeccakFunctionManager()
