#!/usr/bin/env python
# SPDX-License-Identifier: GTDGmbH
"""Module for configuration of the ocgraph package."""

from .logger import OCGraphLogger, logging_preset

from .architecture.architecture import Architecture
from .architecture.x86 import X86Architecture
from .architecture.arm import ArmArchitecture
from .architecture.sparc import SparcArchitecture
from .architecture.ppc import PpcArchitecture

from .disassembler.disassembler import Disassembler
from .disassembler.objdump_sparc import ObjDumpSparcDisassembler
from .disassembler.objdump_ppc import ObjDumpPpcDisassembler
from .disassembler.gdb_default import GdbDisassembler
from .disassembler.objdump_x86 import ObjDumpx86Disassembler
from .disassembler.objdump_arm import ObjDumpArmDisassembler

# fmt: off
disassembler_option: dict[str, dict] = {
    "OBJDUMP": {
        "sparc": ObjDumpSparcDisassembler(),
        "ppc": ObjDumpPpcDisassembler(),
        "x86": ObjDumpx86Disassembler(),
        "arm": ObjDumpArmDisassembler(),
    },
    "GDB": {
        "sparc": GdbDisassembler(),
        "ppc": GdbDisassembler(),
        "x86": GdbDisassembler(),
        "arm": GdbDisassembler(),
    },
}

architecture_option: dict[str, dict] = {
    "x86": {
        "platform": "X86",
        "architecture": X86Architecture(),
    },
    "arm": {
        "platform": "ARM",
        "architecture": ArmArchitecture(),
    },
    "sparc": {
        "platform": "SPARC",
        "architecture": SparcArchitecture(),
    },
    "ppc": {
        "platform": "PPC",
        "architecture": PpcArchitecture(),
    },
}
# fmt: on


class OcGraphConfiguration:
    """Implement configuration presets for the ASM2CFG tool."""

    logger: OCGraphLogger
    """Logging mechanism for module"""
    architecture: Architecture
    """Target architecture instance"""
    disassembler: Disassembler
    """Target disassembler tool like OBJDump, GDB, ..."""

    def __init__(self, arch: str = "sparc", disassembler: str = "OBJDUMP", preset="default"):
        if architecture_option.get(arch) is None:
            raise NotImplementedError("Architecture option not supported!")
        if disassembler_option.get(disassembler) is None:
            raise NotImplementedError("Disassembler option not supported!")
        if logging_preset.get(preset) is None:
            raise NotImplementedError("Logging preset not supported!")

        # load module preset
        _preset = architecture_option[arch]
        _preset["disassembler"] = disassembler_option[disassembler][arch]
        self.__dict__ = _preset

        # configure logging
        self.logger = OCGraphLogger("OcGraph", preset, "asm2cfg.log")

    @staticmethod
    def architectures():
        """Return all available architectures options"""
        return architecture_option.keys()

    @staticmethod
    def disassemblers():
        """Return all available disassemblers options"""
        return disassembler_option.keys()

    @staticmethod
    def loggers():
        """Return all available disassemblers options"""
        return logging_preset.keys()
