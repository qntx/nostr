/** Delete oldest-inserted keys until `collection.size <= max`, calling `onEvict` for each. */
export function trimOldest<K>(
  collection: Map<K, unknown> | Set<K>,
  max: number,
  onEvict?: (key: K) => void,
): void {
  for (const key of collection.keys()) {
    if (collection.size <= max) {
      return;
    }
    onEvict?.(key);
    collection.delete(key);
  }
}

/** Re-insert at the newest end (Map/Set insertion order as recency). */
export function touchKey<K, V>(map: Map<K, V>, key: K, value: V): void {
  map.delete(key);
  map.set(key, value);
}

export function addToSetMap<K, V>(map: Map<K, Set<V>>, key: K, value: V): void {
  let set = map.get(key);
  if (!set) {
    set = new Set();
    map.set(key, set);
  }
  set.add(value);
}

/** Removes `value` and deletes the set once it is empty. */
export function removeFromSetMap<K, V>(map: Map<K, Set<V>>, key: K, value: V): void {
  const set = map.get(key);
  if (!set) {
    return;
  }
  set.delete(value);
  if (set.size === 0) {
    map.delete(key);
  }
}
