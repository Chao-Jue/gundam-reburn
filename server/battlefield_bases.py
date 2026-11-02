"""Explicit local stronghold definitions; not recovered original mission balance."""
MSMA_ID = 777201
MODEL_ID = 601030301  # 0601 * 1,000,000 + 0303 * 100 + variant 01


def character_row(template):
    row = list(template)
    row[0], row[1] = MSMA_ID, MODEL_ID
    row[5], row[6], row[7] = '本据点（本地关联实验）', 'Local stronghold', 'EX_STRONGHOLD'
    row[35] = 'STRONGHOLD'  # 54EF50 -> +150; 4537E0 selects the minimap icon independently
    row[38], row[44] = 0, 0  # no GM weapon set or shield on a static base
    return row


def model_row(template):
    row = list(template)
    row[0] = MODEL_ID
    return row
