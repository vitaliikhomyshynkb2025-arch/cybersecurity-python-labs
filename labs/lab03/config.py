"""Предметна область та числові обмеження варіанта 8."""

from sys import float_info

from shared.student import VARIANT_NUMBER

if VARIANT_NUMBER != 8:
    raise RuntimeError("Застосунок ЛР3 реалізує варіант 8.")

SUBJECT = "Облік часу відновлення сервісів"
UNIT = "minutes"
THRESHOLD = 60.0
VALUE_MAX = float_info.max
