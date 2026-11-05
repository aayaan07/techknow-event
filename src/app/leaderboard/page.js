"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { subscribeToLeaderboard } from "@/lib/leaderboard";

const medals = ["🥇", "🥈", "🥉"];

export default function LeaderboardPage() {
  const [teams, setTeams] = useState(null);
  const [error, setError] = useState("");

  useEffect(
    () =>
      subscribeToLeaderboard(setTeams, (e) =>
        setError(e.message || "Could not load leaderboard.")
      ),
    []
  );

  // Standard competition ranking: equal points share a rank.
  const ranked = (teams || []).map((t, i, arr) => ({
    ...t,
    rank: i > 0 && arr[i - 1].points === t.points ? null : i + 1,
  }));
  ranked.forEach((t, i) => {
    if (t.rank === null) t.rank = ranked[i - 1].rank;
  });

  return (
    <div style={{ minHeight: "100vh", background: "#101220", color: "#fff", padding: 16 }}>
      <div style={{ maxWidth: 640, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h1 style={{ fontSize: 24, fontWeight: 800 }}>🏆 Team Leaderboard</h1>
          <Link href="/" style={{ color: "#118ab2" }}>← Back to hunt</Link>
        </div>
        <p style={{ opacity: 0.6, fontSize: 13, margin: "4px 0 16px" }}>Live · updates automatically</p>

        {error && <div style={{ color: "#ff5470" }}>{error}</div>}
        {!error && teams === null && <div style={{ opacity: 0.7 }}>Loading…</div>}
        {teams?.length === 0 && <div style={{ opacity: 0.7 }}>No teams on the board yet.</div>}

        <ol style={{ listStyle: "none", padding: 0, display: "grid", gap: 8 }}>
          {ranked.map((t) => (
            <li
              key={t.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                background: "#191b2e",
                borderRadius: 12,
                padding: "12px 16px",
                border: t.rank <= 3 ? "1px solid #ffd166" : "1px solid transparent",
              }}
            >
              <span style={{ width: 36, fontSize: 20, fontWeight: 700 }}>
                {medals[t.rank - 1] || `#${t.rank}`}
              </span>
              <span style={{ flex: 1, fontWeight: 600, overflowWrap: "anywhere" }}>
                {t.name}
                <small style={{ display: "block", opacity: 0.55, fontWeight: 400 }}>
                  {t.checkpoints} / 3 checkpoints
                </small>
              </span>
              <span style={{ fontWeight: 800, fontSize: 18 }}>{t.points} pts</span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
