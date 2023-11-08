

class Preconditions:
    @staticmethod
    def check_not_null(x):
        assert (x is not None)
        return x
    
    @staticmethod
    def check_not_null_or_empty(x: str) -> str:
        assert(x is not None)
        assert(x != "")
        return x
