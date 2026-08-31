class AgentError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
