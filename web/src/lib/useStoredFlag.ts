import { useCallback, useSyncExternalStore } from "react";

const listeners = new Set<() => void>();

function read(key: string): boolean | null {
  try {
    const v = window.localStorage.getItem(key);
    return v === "1" ? true : v === "0" ? false : null;
  } catch {
    return null;
  }
}

/** Boolesches UI-Flag in localStorage (null = nie gesetzt). Ohne Speicher (privater Modus) bleibt es bei null. */
export function useStoredFlag(key: string): [boolean | null, (v: boolean) => void] {
  const value = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      window.addEventListener("storage", cb);
      return () => {
        listeners.delete(cb);
        window.removeEventListener("storage", cb);
      };
    },
    () => read(key),
    () => null,
  );
  const set = useCallback(
    (v: boolean) => {
      try {
        window.localStorage.setItem(key, v ? "1" : "0");
      } catch {
        // Speicher gesperrt: das Flag gilt dann nur bis zum Neuladen nicht – akzeptabel für eine Komfortfunktion.
      }
      listeners.forEach((l) => l());
    },
    [key],
  );
  return [value, set];
}
