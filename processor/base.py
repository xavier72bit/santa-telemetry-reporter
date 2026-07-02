# -*- coding: UTF-8 -*-
from abc import ABC, abstractmethod
from typing import Generic, TypeVar


InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


class Processor(ABC, Generic[InputT, OutputT]):
    @abstractmethod
    def analyze(self, data: InputT) -> OutputT:
        raise NotImplementedError
