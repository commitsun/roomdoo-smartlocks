from abc import ABC, abstractmethod

class SmartLockProvider(ABC):

    @abstractmethod
    def get_token(self):
        pass

    @abstractmethod
    def open_lock(self, lockId):
        pass

    @abstractmethod
    def get_lock_passwords(self, lockId):
        pass

    @abstractmethod
    def create_random_password(self, lockId, effectiveTime, invalidTime):
        pass

    @abstractmethod
    def create_custom_password(self, lockId, password, effectiveTime, invalidTime):
        pass

    @abstractmethod
    def extend_password(self, lockId, passwordId, effectiveTime, invalidTime):
        pass

    @abstractmethod
    def delete_password(self, lockId, passwordId):
        pass