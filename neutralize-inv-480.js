// personal_thought_capacity_harder.js
'use strict';

const moduleName = null;
const base = moduleName ? Module.getBaseAddress(moduleName) : Process.enumerateModules()[0].base;

function addr(rva) {
  return base.add(ptr(rva));
}

function patchReturnTrue(name, rva) {
  const p = base.add(ptr(rva));

  Memory.patchCode(p, 16, code => {
    const w = new X86Writer(code, { pc: p });
    w.putMovRegU32('eax', 1);
    w.putRet();
    w.flush();
  });

  console.log(`[+] ${name}: forced true @ ${p}`);
}

function patchBytes(name, rva, expectedHex, replacementHex) {
  const p = base.add(ptr(rva));
  const expected = expectedHex.replace(/\s+/g, '').toLowerCase();
  const replacement = replacementHex.replace(/\s+/g, '').toLowerCase();
  const current = p.readByteArray(expected.length / 2);
  const currentHex = Array.from(new Uint8Array(current))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  if (currentHex === replacement) {
    console.log(`[=] ${name}: already patched @ ${p}`);
    return;
  }

  if (currentHex !== expected) {
    console.log(`[!] ${name}: bytes mismatch @ ${p}`);
    console.log(`    got      ${currentHex.match(/../g).join(' ')}`);
    console.log(`    expected ${expected.match(/../g).join(' ')}`);
    return;
  }

  Memory.patchCode(p, replacement.length / 2, code => {
    code.writeByteArray(replacement.match(/../g).map(x => parseInt(x, 16)));
  });

  console.log(`[+] ${name}: patched @ ${p}`);
}

// Hard-return predicates before they can set "not enough SCU" / invalid move data.
patchReturnTrue('CheckCanFitInContainer', '0x4F99070');
patchReturnTrue('InventoryUtils::CanStoreItemInInventory', '0x004F3BC0');
patchReturnTrue('InventoryUtils::CanFitItemDimensionsInContainer', '0x004F3170');

patchReturnTrue('CSCPersonalThoughtDisplay::CanFitInContainer(SInventoryId)', '0x4F968F0');
patchReturnTrue('CSCPersonalThoughtDisplay::CanFitInContainer(IEntityPtr)', '0x4F96A30');
patchReturnTrue('CSCPersonalThoughtDisplay::WillItemQuickMove', '0x505D6C0');

patchReturnTrue('PersonalInventoryUtils::CanContainerStoreEntities', '0x5E54150');
patchReturnTrue('CSCLocalPlayerPersonalThoughtComponent::CanStoreItemInLocation(class)', '0x62B3C60');
patchReturnTrue('CSCLocalPlayerPersonalThoughtComponent::CanStoreItemInLocation(entity)', '0x62B3DF0');

patchReturnTrue('CSCLocalPlayerPersonalThoughtComponent::CheckDropInteractionConditions', '0x62B4510');
patchReturnTrue('SInteractionConditionCanDropItemInCurrentZone::ResolveCondition', '0x6344950');
patchReturnTrue('SInteractionConditionCanDropWearableItem::ResolveCondition', '0x6344990');

// Extra: neutralize the raw capacity-fail branch inside CanStoreItemInInventory.
// Original: jg fail after comparing usage against capacity.
patchBytes(
  'CanStoreItemInInventory capacity jg fail',
  '0x004F3C02',
  '7F 39',
  '90 90'
);

// Extra: CheckCanFitInContainer ratio branch/message path.
// Original code computes used/max ratio and then may enter message-building block.
// These make the capacity/dimension result look successful at the branch level too.
patchBytes(
  'CheckCanFitInContainer dimension fail branch',
  '0x4F99153',
  '74 08',
  '90 90'
);

patchBytes(
  'CheckCanFitInContainer not-enough-capacity fail branch',
  '0x4F99157',
  '74 04',
  '90 90'
);

// Optional: mutate displayed/consumed capacity field whenever CheckCanFitInContainer is called.
// This is the direct "used capacity negative" version.
Interceptor.attach(addr('0x4F99070'), {
  onEnter(args) {
    const targetContainer = args[2];
    if (!targetContainer.isNull()) {
      targetContainer.add(0x218).writeU8(1);                  // maxCapacity has dirty value
      targetContainer.add(0x238).writeS64(0x7fffffff);        // max capacity huge
      targetContainer.add(0x1490).writeS64(-0x10000000);      // used capacity negative
    }
  }
});

patchBytes(
  'QuickLoot lambda: force CheckCanFit result true',
  '0x4F7B229',
  '44 0F B6 E0',
  '41 B4 01 90'
);

patchBytes(
  'QuickLoot lambda: force fallback v25 true',
  '0x4F7B22F',
  '45 32 E4',
  '41 B4 01'
);

patchBytes(
  'QuickLoot lambda: skip invalid move branch',
  '0x4F7B375',
  '0F 84 A0 00 00 00',
  '90 90 90 90 90 90'
);

patchBytes(
  'PersonalThought: skip grouped-container visibility filter',
  '0x631E3CD',
  '75 2A',
  'EB 2A'
);

patchReturnTrue(
  'PersonalThought: grouped container predicate always true',
  '0x626C130'
);

patchReturnTrue(
  'PersonalThought: ValidateInventoryContainer always true',
  '0x636DE80'
);

patchBytes(
  'PersonalThought: disable large-container UI gate',
  '0x5054406',
  '7D 1A',
  '90 90'
);

patchBytes(
  'Storage terminal: do not apply container excluded item types',
  '0x633F6FE',
  'E8 0D 9E 1D FE',
  '90 90 90 90 90'
);

patchBytes(
  'CInventoryContainerComponent::GetExcludedItemTypes: return empty',
  '0x4519510',
  '48',
  'C3'
);

console.log(`[+] harder PersonalThought capacity bypass loaded. Base=${base}`);
