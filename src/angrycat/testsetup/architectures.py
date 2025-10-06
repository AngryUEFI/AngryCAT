"""
Predefined CPU architectures for AMD Zen processors.
"""

from .base import Architecture


# AMD Zen architecture variants
# All Zen variants share the ucode_revision_msr at 0x8b

Zen1 = Architecture(
    name="Zen1",
    ucode_revision_msr=0x8b,
    family=0x17,
    model_range=(0x00, 0x0F),
    vendor="AMD",
)

Zen2 = Architecture(
    name="Zen2",
    ucode_revision_msr=0x8b,
    family=0x17,
    model_range=(0x30, 0x3F),
    vendor="AMD",
)

Zen3 = Architecture(
    name="Zen3",
    ucode_revision_msr=0x8b,
    family=0x19,
    model_range=(0x00, 0x0F),
    vendor="AMD",
)

Zen4 = Architecture(
    name="Zen4",
    ucode_revision_msr=0x8b,
    family=0x19,
    model_range=(0x60, 0x6F),
    vendor="AMD",
)

Zen5 = Architecture(
    name="Zen5",
    ucode_revision_msr=0x8b,
    family=0x1A,
    model_range=(0x00, 0x0F),
    vendor="AMD",
)
