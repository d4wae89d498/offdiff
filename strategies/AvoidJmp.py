from offdiff import *



class AvoidJmpStrategy(AddressMatchingAbstractStrategy):

    def get_new_address_candidates(self, old_address, old_binary, new_binary, pattern = None):
            raise NotImplementedError("todo")