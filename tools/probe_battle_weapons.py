"""Read-only current-client equipment fields; pointers do not prove rendering."""


def weapon_state(reader, actor):
    # 483EA0 passes actor+35C to 4E72A0; 4E3100 selects these inline slots.
    component = reader.u32(actor + 0x35c)
    if not component:
        return {'component': component, 'slots': []}
    alternate = reader.u8(component + 0x1318)
    index = reader.u32(component + 0xea0)
    slots = []
    for slot in range(3):
        address = component + 0x144 + slot * 0x474
        definition = reader.u32(address + 4)
        slots.append({
            'slot': slot, 'address': address,
            'item_id': reader.u32(address), 'definition': definition,
            'native_slot': reader.u32(address + 8),
            'resources': ([reader.u32(definition + offset) for offset in (4, 8, 12)]
                          if definition else None),
            'definition_flags': reader.u32(definition + 0x974) if definition else None,
            'motion_layer': reader.u32(definition + 0x30) if definition else None,
            'motion_class': reader.u32(definition + 0x34) if definition else None,
        })
    return {'component': component, 'equip_index': index,
            'alternate_active': alternate,
            'effective_equip_index': -1 if alternate else index,
            'slots': slots}


def weapon_visuals(reader, actor):
    # 4E0DE0 traverses manager+10: node+0 next, node+8 visual object.
    manager = reader.u32(actor + 0xb4)
    result = {'manager': manager, 'objects': []}
    if not manager:
        return result
    head = reader.u32(manager + 0x10)
    node = reader.u32(head) if head else None
    seen = set()
    while node and node != head and node not in seen and len(seen) < 32:
        seen.add(node)
        obj = reader.u32(node + 8)
        if obj:
            raw = reader.read(obj, 0x80)
            result['objects'].append({'object': obj, 'vtable': reader.u32(obj),
                                      'item_id': reader.u32(obj + 8),
                                      # Base and derived classes share +1C;
                                      # 4E1830 tests this render-model pointer.
                                      'render_model': reader.u32(obj + 0x1c),
                                      'loaded_model': (reader.u32(obj + 0x68)
                                                       if reader.u32(obj) == 0xcb5e54 else None),
                                      'raw': raw.hex() if raw else None})
        node = reader.u32(node)
    result['truncated'] = bool(node and node != head)
    return result
