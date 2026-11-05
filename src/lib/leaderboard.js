import {
  doc,
  runTransaction,
  serverTimestamp,
  collection,
  query,
  orderBy,
  onSnapshot,
} from "firebase/firestore";
import { db } from "./firebase";

// Points awarded per checkpoint. Round 2 checkpoints are worth more.
export const POINTS_BY_ROUND = { 1: 100, 2: 150 };

export const teamKey = (name) =>
  name.trim().toLowerCase().replace(/\s+/g, "-");

// Idempotent: a checkpoint is only counted once per team.
export async function awardCheckpoint(teamName, cpId, round) {
  if (!db) return { skipped: true };
  const points = POINTS_BY_ROUND[round] ?? 100;
  const ref = doc(db, "teams", teamKey(teamName));
  await runTransaction(db, async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists() ? snap.data() : null;
    if (data?.cleared?.[cpId]) return;
    const cleared = { ...(data?.cleared || {}), [cpId]: points };
    tx.set(ref, {
      name: data?.name || teamName.trim(),
      cleared,
      checkpoints: Object.keys(cleared).length,
      points: (data?.points || 0) + points,
      updatedAt: serverTimestamp(),
    });
  });
  return { skipped: false, points };
}

export function subscribeToLeaderboard(onData, onError) {
  if (!db) {
    onError?.(new Error("Firebase is not configured."));
    return () => {};
  }
  const q = query(
    collection(db, "teams"),
    orderBy("points", "desc"),
    orderBy("updatedAt", "asc")
  );
  return onSnapshot(
    q,
    (snap) => onData(snap.docs.map((d) => ({ id: d.id, ...d.data() }))),
    onError
  );
}
